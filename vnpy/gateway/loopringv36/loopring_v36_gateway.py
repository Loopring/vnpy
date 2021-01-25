"""
Gateway for Loopring v36 Crypto Exchange.
"""

import urllib
import hashlib
import hmac
import time
import ujson
from copy import copy
from datetime import datetime, timedelta
from enum import Flag
from threading import Lock
from operator import itemgetter
from random import randint
from typing import Any, Sequence
import re

from vnpy.api.rest import RestClient, Request
from vnpy.api.websocket import WebsocketClient
from vnpy.trader.constant import (
    Direction,
    Exchange,
    Product,
    Status,
    OrderType,
    Interval
)
from vnpy.trader.gateway import BaseGateway
from vnpy.trader.object import (
    TickData,
    OrderData,
    TradeData,
    AccountData,
    ContractData,
    BarData,
    OrderRequest,
    CancelRequest,
    SubscribeRequest,
    HistoryRequest
)
from vnpy.trader.event import EVENT_TIMER
from vnpy.trader.setting import SETTINGS
from vnpy.event import Event
from vnpy.gateway.loopringv36.loopring_orderId_manager import BaseOrderIdManager
from vnpy.gateway.loopringv36.eddsa_utils import *

from vnpy.gateway.loopring.ethsnarks.eddsa import PoseidonEdDSA
from vnpy.gateway.loopring.ethsnarks.field import FQ, SNARK_SCALAR_FIELD
from vnpy.gateway.loopring.ethsnarks.poseidon import poseidon_params, poseidon
import sys
from time import sleep
from pathlib import Path

REST_HOST = "https://api3.loopring.io"
WEBSOCKET_TRADE_HOST = "wss://ws.api3.loopring.io/v3/ws"
WEBSOCKET_DATA_HOST =  "wss://ws.api3.loopring.io/v3/ws"

STATUS_LOOPRING2VT = {
    "processing": Status.NOTTRADED,
    "filled"    : Status.PARTTRADED,
    "processed" : Status.ALLTRADED,
    "cancelling": Status.CANCELLING,
    "cancelled" : Status.CANCELLED,
    "expired"   : Status.EXPIRED
}

ORDERTYPE_VT2LOOPRING = {
    OrderType.LIMIT: "LIMIT",
    OrderType.MARKET: "MARKET"
}
ORDERTYPE_LOOPRING2VT = {v: k for k, v in ORDERTYPE_VT2LOOPRING.items()}

DIRECTION_VT2LOOPRING = {
    Direction.LONG: "BUY",
    Direction.SHORT: "SELL"
}
DIRECTION_LOOPRING2VT = {v: k for k, v in DIRECTION_VT2LOOPRING.items()}

INTERVAL_VT2LOOPRING = {
    Interval.MINUTE: "1m",
    Interval.HOUR: "1h",
    Interval.DAILY: "1d",
}

TIMEDELTA_MAP = {
    Interval.MINUTE: timedelta(minutes=1),
    Interval.HOUR: timedelta(hours=1),
    Interval.DAILY: timedelta(days=1),
}


class Security(Flag):
    NONE = 0
    SIGNED = 1
    API_KEY = 2
    ECDSA_SIGN = 4

symbol_name_map = {}

class LoopringV36Gateway(BaseGateway):
    """
    VN Trader Gateway for Loopring connection.
    """

    default_setting = {
        "key": "",
        "secret": "",
        "session_number": 3,
        "proxy_host": "",
        "proxy_port": 0,
        "address": "",
    }

    exchanges = [Exchange.LOOPRINGV36]

    MAX_ORDER_ID = 0xFFFFFFFF

    def __init__(self, event_engine):
        """Constructor"""
        super().__init__(event_engine, "LOOPRINGV36")

        self.subscribe_reqs = {}

        # Max subcribe ws can be up to 3 for triangle algo
        self.trade_ws_apis = [LoopringTradeWebsocketApi(self)]
        self.market_ws_apis = [LoopringDataWebsocketApi(self)]
        self.rest_api = LoopringRestApi(self)

        # order records
        self.orders = {}
        self.orderIdHashMap = {}

        # self.event_engine.register(EVENT_TIMER, self.process_timer_event)

    def connect(self, setting: dict):
        """"""
        proxy_host = setting.get("proxy_host", "")
        proxy_port = setting.get("proxy_port", "")

        self.rest_api.connect(setting)
        for market_ws_api in self.market_ws_apis:
            market_ws_api.connect(proxy_host, proxy_port)
        for trace_ws_api in self.trade_ws_apis:
            trace_ws_api.connect(WEBSOCKET_DATA_HOST, proxy_host, proxy_port)

    def subscribe(self, req: SubscribeRequest):
        """"""
        self.write_log(f"loopring gateway subscribe {req}")
        if req.symbol in self.subscribe_reqs:
            self.write_log(f"ERROR: already subscribed {len(self.subscribe_reqs)} sources {self.subscribe_reqs}")
            return

        tokens = req.symbol.split('-')
        for t in tokens:
            assert t in self.rest_api.tokens
            tokenId = self.rest_api.tokens[t].tokenId
            self.rest_api.get_storageId(tokenId)

        self.trade_ws_apis[0].subscribe(req)
        self.market_ws_apis[0].subscribe(req)
        self.subscribe_reqs[req.symbol] = req

    def send_order(self, req: OrderRequest):
        """"""
        return self.rest_api.send_order(req)

    def send_orders(self, reqs: Sequence[OrderRequest]):
        """"""
        return self.rest_api.send_orders(reqs)

    def cancel_order(self, req: CancelRequest):
        """"""
        if req.orderid in self.orders or req.orderid == "*":
            self.rest_api.cancel_order(req)

    def cancel_orders(self, reqs: Sequence[CancelRequest]):
        """"""
        self.rest_api.cancel_orders(reqs)

    def query_ws_key(self):
        """"""
        return self.rest_api.query_ws_key()

    def query_account(self):
        """"""
        pass

    def query_position(self):
        """"""
        pass

    def query_history(self, req: HistoryRequest):
        """"""
        return self.rest_api.query_history(req)

    def close(self):
        """"""
        self.rest_api.stop()
        for ws_api in self.trade_ws_apis:
            ws_api.stop()
        for ws_api in self.market_ws_apis:
            ws_api.stop()

    def on_order(self, order: OrderData, hash = None):
        """"""
        if order.is_active():
            self.orders[order.orderid] = order
            if hash is not None:
                self.orderIdHashMap[order.orderid] = hash
        elif order.status in [Status.CANCEL_REJECT, Status.CANCELLING]:
            # this mean the order is still active in srv, and will
            # be cancelled soon, so we keep order for a while.
            pass
        else:
            self.orders.pop(order.orderid, None)
            self.orderIdHashMap.pop(order.orderid, None)
        super().on_order(order)

    def process_timer_event(self, event: Event):
        """"""
        #TODO: handle timeout

    def reset_loopring_connection(self):
        return self.rest_api.reset_loopring_connection()

# class LoopringRestApi(AsyncRestClient):
class LoopringRestApi(RestClient):
    """
    LOOPRING REST API
    """

    def __init__(self, gateway: LoopringV36Gateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name

        self.trade_ws_apis = self.gateway.trade_ws_apis

        self.key = ""
        self.secret = ""

        self.user_stream_key = ""
        self.keep_alive_count = 0
        self.recv_window = 5000
        self.time_offset = 0

        self.order_count = 0
        self.orderId_limit = self.gateway.MAX_ORDER_ID
        self.order_count_lock = Lock()
        self.connect_time = 0

        self.address = ""
        self.publicKeyX = ""
        self.publicKeyY = ""
        self.lrcTokenId = 2
        self.ethTokenId = 0
        self.accountId = 0

        self.failed_orderId = {} # {tokenSId:[reused orderId list]}
        self.contracts = {}
        self.tokens = {}

        self.orderId_manager = BaseOrderIdManager()
        self.offchainId_manager = BaseOrderIdManager()


    def _order_params(self, request):
        """
        Convert params based on https://developers.infogr.am/rest/request-signing.html
        """
        method = request.method
        url = urllib.parse.quote(REST_HOST + request.path, safe='')
        data = urllib.parse.quote("&".join([f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in request.params.items()]), safe='')
        return "&".join([method, url, data])

    def sign(self, request):
        """
        Generate LOOPRING signature.
        """
        security = request.data.pop("security", Security.NONE)
        if security == Security.NONE:
            if request.method == "POST":
                request.data = ujson.dumps(request.params if len(request.data) == 0 else request.data)
                request.params = {}
            return request

        path = request.path
        if request.params:
            if request.method in ["GET", "DELETE"]:
                path = request.path + "?" + urllib.parse.urlencode(request.params, safe=',')
        else:
            request.params = dict()

        # Add headers
        default_headers = {
            "Content-Type": "*/*",
            "Accept": "application/json",
            'User-Agent': "Trade Robot User-Agent",
            "X-API-KEY": self.key,
        }
        if request.headers != None:
            default_headers.update(request.headers)

        if security & Security.SIGNED:
            ordered_data = self._order_params(request)
            hasher = hashlib.sha256()
            hasher.update(ordered_data.encode('utf-8'))
            msgHash = int(hasher.hexdigest(), 16) % SNARK_SCALAR_FIELD
            # print("order_data =", ordered_data, "hash =", hex(msgHash))
            signed = PoseidonEdDSA.sign(msgHash, FQ(int(self.eddsaKey, 16)))
            signature = "0x" + "".join([
                                            hex(int(signed.sig.R.x))[2:].zfill(64),
                                            hex(int(signed.sig.R.y))[2:].zfill(64),
                                            hex(int(signed.sig.s))[2:].zfill(64)
                                        ])
            default_headers.update({"X-API-SIG": signature})
        elif security & Security.ECDSA_SIGN:
            default_headers.update({"X-API-SIG": request.data["ecdsaSig"]})
            pass

        request.path = path
        if request.method != "GET":
            request.data = ujson.dumps(request.params if len(request.data) == 0 else request.data)
            request.params = {}
        else:
            request.data = ujson.dumps({})

        # if security in [Security.SIGNED, Security.API_KEY]:
        request.headers = default_headers

        # self.gateway.write_log(f"finish sign {request.path}")
        return request

    def connect(
            self,
            exported_secret: dict
    ):
        """
        Initialize connection to LOOPRING REST server.
        """
        self.api_key    = exported_secret['apiKey']
        self.eddsaKey   = exported_secret['eddsaKey']
        # self.ecdsaKey   = int(exported_secret['ecdsaKey'], 16).to_bytes(32, byteorder='big')
        self.address    = exported_secret['accountAddress']
        self.accountId  = exported_secret['accountId']
        self.publicKeyX = exported_secret["publicKeyX"]
        self.publicKeyY = exported_secret["publicKeyY"]
        self.exchange   = exported_secret['exchangeAddress']
        self.key        = exported_secret['apiKey']

        self.next_eddsaKey = None

        self.ammJoinfeeBips = 0.001
        self.ammPools = {}

        self.connect_time = (
            int(datetime.now().strftime("%y%m%d%H%M%S")) * self.orderId_limit
        )

        proxy_host = exported_secret.get('proxy_host', "")
        proxy_port = exported_secret.get('proxy_port', "")
        session_number = exported_secret.get('session_number', 3)
        self.init(REST_HOST, proxy_host, proxy_port)
        self.start(session_number)

        self.gateway.write_log("REST API启动成功")

        self.gateway.write_log("start query_time")
        self.query_time()
        self.gateway.write_log("start query_token")
        self.query_market_config()
        self.gateway.write_log("start query_account")
        self.query_account()
        self.gateway.write_log("query_account connect")

    def query_ws_key(self):
        # TODO
        data = {
            "security": Security.NONE
        }

        response = self.request(
            "GET",
            path="/v3/ws/key",
            data=data
        )
        json_resp = response.json()
        return json_resp['key']

    def query_time(self):
        """"""
        data = {
            "security": Security.NONE
        }

        added_request = self.add_request(
            "GET",
            path="/api/v3/timestamp",
            callback=self.on_query_time,
            data=data
        )

    def query_account(self):
        """"""
        data = {
            "security": Security.NONE
        }
        param = {
            "owner": self.address
        }

        self.add_request(
            method="GET",
            path="/api/v3/account",
            callback=self.on_query_account,
            params=param,
            data=data
        )

    def query_apikey(self):
        """"""
        data = {"security": Security.SIGNED}

        param = {
            "accountId": self.accountId,
        }

        self.add_request(
            method="GET",
            path="/api/v3/apiKey",
            callback=self.on_query_apikey,
            params=param,
            data=data
        )

    def query_balance(self):
        """"""
        data = {"security": Security.API_KEY}

        param = {
            "accountId": self.accountId,
            "tokens": ','.join([str(token.tokenId) for token in self.tokens.values()])
        }

        self.add_request(
            method="GET",
            path="/api/v3/user/balances",
            callback=self.on_query_balance,
            params=param,
            data=data
        )

    def query_order(self, hash):
        """"""
        data = {"security": Security.API_KEY}

        params = {
            "accountId": self.accountId,
            "hash" : hash
        }

        self.add_request(
            method="GET",
            path="/api/v2/order",
            callback=self.on_query_order,
            params=params,
            data=data
        )

    def query_orders(self, offset = 0):
        """"""
        data = {"security": Security.API_KEY}

        params = {
            "accountId": self.accountId,
            "start" : 0,
            "end" : (int(time.time()) - self.time_offset) * 1000,
            "status": "processing",
            "limit" : 50,
            "offset": offset
        }

        self.add_request(
            method="GET",
            path="/api/v3/orders",
            callback=self.on_query_orders,
            params=params,
            data=data,
            extra=offset
        )

    def query_market_config(self):
        """
            query market token and contract config
        """
        data = {"security": Security.NONE}

        params = {}

        self.add_request(
            method="GET",
            path="/api/v3/exchange/tokens",
            callback=self.on_query_token,
            params=params,
            data=data
        )

    def query_contract(self):
        """
            hardcode information as marketInfo API is gone.
        """
        data = {"security": Security.NONE}

        params = {}

        self.add_request(
            method="GET",
            path="/api/v3/exchange/markets",
            callback=self.on_query_contract,
            params=params,
            data=data
        )

    def _new_order_id(self):
        """"""
        with self.order_count_lock:
            self.order_count += 1
            return self.order_count

    def _create_order(self, req):
        bsStr = req.symbol.split("-")
        if not req.symbol in self.contracts:
            self.gateway.write_log("Market dont have " + req.symbol)
            return False, None, None

        if not req.volume:
            self.gateway.write_log(f"{req} is invalid")
            return False, None, None

        contractS = self.tokens[bsStr[0]]
        contractB = self.tokens[bsStr[1]]
        amountS = str(int(10 ** contractS.decimals * req.volume))
        amountB = str(int(10 ** contractB.decimals * req.price * req.volume))
        tokenSId = contractS.tokenId
        tokenBId = contractB.tokenId
        buy = req.direction == Direction.LONG
        if buy:
            tokenSId, tokenBId = tokenBId, tokenSId
            amountS, amountB = amountB, amountS

        clientOrderId = "liquidmining" + str(self.connect_time + self._new_order_id())
        vt_order = req.create_order_data(
            orderid=clientOrderId,
            gateway_name=self.gateway_name
        )

        if tokenSId in self.failed_orderId and len(self.failed_orderId[tokenSId]) > 0:
            orderId = self.failed_orderId[tokenSId].pop(0)
        else:
            orderId = self.orderId_manager.get_orderId(tokenSId)

        # ahead 1 hour
        validSince = int(time.time()) - self.time_offset - 3600
        validUntil = 1700000000 #validSince + 60 * 24 * 60 * 60
        maxFeeBips = 50

        # order base
        newOrder = {
            # sign part
            "exchange"      : self.exchange,
            "accountId"     : self.accountId,
            "storageId"     : orderId,
            "sellToken": {
                "tokenId": tokenSId,
                "volume": amountS
            },
            "buyToken" : {
                "tokenId": tokenBId,
                "volume": amountB
            },
            "validUntil"    : validUntil,
            "maxFeeBips"    : maxFeeBips,
            "fillAmountBOrS": buy,
            # "taker"         : "0000000000000000000000000000000000000000",
            # aux data
            "allOrNone"     : False,
            "clientOrderId" : clientOrderId,
            "orderType"     : "LIMIT_ORDER"
        }

        signer = OrderEddsaSignHelper(self.eddsaKey)
        msgHash = signer.hash(newOrder)
        signedMessage = signer.sign(newOrder)
        # update signaure
        newOrder.update({
            "hash"           : hex(msgHash),
            "eddsaSignature" : signedMessage
        })

        self.gateway.write_log(f"Order: {req.direction} {req.price} {req.volume} orderId {orderId} clientOrderId {clientOrderId}")
        self.gateway.on_order(vt_order, msgHash)
        # self.gateway.write_log(f"create new order {newOrder}")
        return True, vt_order, newOrder

    def send_order(self, req: OrderRequest):
        """"""
        data = {
            "security": Security.API_KEY
        }

        ok, order, newOrder = self._create_order(req)
        if not ok:
            return ""

        headers = {
            "Content-Type": "application/json",
            "X-API-KEY": self.key
        }

        self.add_request(
            method="POST",
            path="/api/v3/order",
            callback=self.on_send_order,
            params=newOrder,
            data=data,
            headers=headers,
            extra=[order],
            on_error=self.on_send_order_error,
            on_failed=self.on_send_order_failed
        )

        return order.vt_orderid

    def cancel_order(self, req: CancelRequest):
        """"""
        self.gateway.write_log(f"cancel_order {req.orderid}")
        data = {
            "security": Security.SIGNED
        }

        params = {
            "accountId": self.accountId,
            # "orderHash": self.clientOrderMap[req.orderid]
            # 'clientOrderId': req.orderid
        }

        if req.orderid != "*":
            params['clientOrderId'] = req.orderid

        self.add_request(
            method="DELETE",
            path="/api/v3/order",
            callback=self.on_cancel_order,
            params=params,
            data=data,
            on_failed=self.on_cancel_order_failed,
            on_error=self.on_cancel_order_error,
        )

    def on_query_time(self, data, request):
        """"""
        self.gateway.write_log(f"on_query_time: {data}")
        local_time = int(time.time() * 1000)
        server_time = int(data["timestamp"])
        self.time_offset = int((local_time - server_time) / 1000)

    def on_query_account(self, data, request):
        """"""
        self.gateway.write_log(f"on_query_account {data}")
        self.accountId  = data['accountId']
        self.publicKeyX = data['publicKey']['x']
        self.publicKeyY = data['publicKey']['y']
        # self.key = account_data['apiKey']

        self.gateway.write_log("账户信息查询成功")

        self.gateway.write_log("start get_apiKey")
        self.query_apikey()

    def on_query_apikey(self, data, request):
        self.gateway.write_log(f"on_query_apikey {data}")
        self.key = data["apiKey"]

        self.gateway.write_log("start query_balance")
        self.query_balance()

        self.gateway.write_log("start query_orders")
        self.query_orders()

    def on_query_balance(self, data, request):
        self.gateway.write_log(f"on_query_balance {data}")
        for balance in data:
            token_symbol = "LRC"
            decimals = 18
            tokenAmount = balance['total']
            frozenAmount = balance['locked']
            for token in self.tokens.keys():
                if self.tokens[token].tokenId == balance['tokenId']:
                    token_symbol = self.tokens[token].symbol
                    decimals = self.tokens[token].decimals
                    account = AccountData(
                        accountid=token_symbol,
                        balance=float(tokenAmount)/(10**decimals),
                        frozen=float(frozenAmount)/(10**decimals),
                        gateway_name=self.gateway_name
                    )
                    self.gateway.write_log(f"账户余额 {account}")
                    self.gateway.on_account(account)

        self.gateway.write_log("账户余额查询成功")

    def on_get_storageId(self, data, request):
        # self.gateway.write_log(f"on_get_storageId {request} {data}")

        tokenId = request.params['sellTokenId']
        self.orderId_manager.put_orderId(tokenId, int(data['orderId']))
        self.offchainId_manager.put_orderId(tokenId, int(data['offchainId']))

    def on_query_order(self, data, request):
        # self.gateway.write_log(f"on_query_orders {data}")
        order = data['data']
        # TODO: use correct decimals to calc volume
        decimals = self.contracts[order['market']].decimals
        volume = int(order["volumes"]["baseAmount"])/(10**decimals)
        traded = int(order["volumes"]["baseFilled"])/(10**decimals)
        order_data = OrderData(
            orderid=order["clientOrderId"],
            symbol=order["market"],
            exchange=Exchange.LOOPRINGV36,
            price=float(order["price"]),
            volume=volume,
            traded=traded,
            type=OrderType.LIMIT,
            direction=DIRECTION_LOOPRING2VT[order["side"]],
            status=STATUS_LOOPRING2VT.get(order["status"], "processing"),
            datetime=datetime.fromtimestamp(float(order['validity']['start'])).__str__(),
            gateway_name=self.gateway_name,
        )
        self.gateway.on_order(order_data, order['hash'])
        self.gateway.write_log(f"Order查询成功:\n{order}")

    def on_query_orders(self, data, request):
        # self.gateway.write_log(f"on_query_orders {data}")

        for order in data['orders']:
            # TODO: use correct decimals to calc volume
            decimals = self.contracts[order['market']].decimals
            volume = int(order["volumes"]["baseAmount"])/(10**decimals)
            traded = int(order["volumes"]["baseFilled"])/(10**decimals)
            order_data = OrderData(
                orderid=order["clientOrderId"],
                symbol=order["market"],
                exchange=Exchange.LOOPRINGV36,
                price=float(order["price"]),
                volume=volume,
                traded=traded,
                type=OrderType.LIMIT,
                direction=DIRECTION_LOOPRING2VT[order["side"]],
                status=STATUS_LOOPRING2VT.get(order["status"], None),
                datetime=datetime.fromtimestamp(float(order['validity']['start'])).__str__(),
                gateway_name=self.gateway_name,
            )
            self.gateway.on_order(order_data, order['hash'])

        if request.extra + len(data['orders']) < data['totalNum']:
            self.query_orders(request.extra + len(data['orders']))
        else:
            self.gateway.write_log("所有Orders查询成功")

    def on_query_token(self, data, request):
        """"""
        self.gateway.write_log(f"on_query_token: {data}")
        for d in data:
            contract = ContractData(
                symbol=d["symbol"],
                name=d["symbol"],
                exchange=Exchange.LOOPRINGV36,
                size=1,
                address=d['address'],
                decimals=d['decimals'],
                tokenId=d['tokenId'],
                product=Product.SPOT,
                pricetick=0.0,
                min_volume=int(d['orderAmounts']['minimum'])/10**int(d['decimals']),
                history_data=True,
                gateway_name=self.gateway_name,
            )
            self.gateway.on_contract(contract)
            self.tokens[d['symbol']] = contract
            # self.get_storageId(d['tokenId'])
        self.gateway.write_log(f"on_query_token success: {self.tokens}")
        self.gateway.write_log("start query_contract")
        self.query_contract()
        # self.query_amm_pools()

    def on_query_contract(self, data, requet):
        self.gateway.write_log(f"on_query_contract: {data}")
        decimals = 18
        for d in data["markets"]:
            tokens = re.match("(\w+)-(\w+)", d['market'])
            assert tokens is not None
            base_token = tokens.groups()[0]
            assert self.tokens[base_token].tokenId == d['baseTokenId']
            decimals = self.tokens[base_token].decimals

            contract = ContractData(
                symbol=d["market"],
                name=d["market"],
                exchange=Exchange.LOOPRINGV36,
                size=1,
                # address=d['address'],
                decimals=decimals,
                # tokenId=d['baseTokenId'],
                min_volume=0.0001,
                product=Product.SPOT,
                pricetick=float(1)/(10**d['precisionForPrice']),
                history_data=True,
                gateway_name=self.gateway_name,
            )
            self.gateway.on_contract(contract)
            self.contracts[d['market']] = contract

            symbol_name_map[contract.symbol] = contract.name

        self.gateway.write_log(f"Contract 信息查询成功 {symbol_name_map}")

    def on_send_order(self, data, request):
        # self.gateway.write_log(f"on_send_order {data} success")
        order = request.extra[0]
        order.status = Status.NOTTRADED
        self.gateway.on_order(order)
        """"""
        pass

    def on_send_order_failed(self, status_code: str, request: Request):
        """
        Callback when sending order failed on server.
        """
        self.gateway.write_log(f"Error: on_send_order_failed: {status_code} {request.response.text}")
        orders = request.extra
        data = request.response.json()
        for order in orders:
            order.status = Status.REJECTED
            # {'error': {'code': 102007, 'message': 'order existed, please check detail order info'}}
            if 'resultInfo' in data and 'order existed' in data['resultInfo']['message']:
                self.gateway.on_order(order)
                return

            newest_order_id = 0
            # if {'error': {'code': 102004, 'message': 'the newest storage id should be 57451'}}
            if 'the newest storage id should be' in data['resultInfo']['message']:
                newest_order_id = re.search('the newest storage id should be (\d+)', data['resultInfo']['message']).groups()[0]

            #align srv orderId
            self.on_error_recover_orderId(request, newest_order_id)
            self.gateway.on_order(order)
            # delay 150ms to avoid high TPS in srv.
            sleep(0.15)

    def on_send_order_error(
            self, exception_type: type, exception_value: Exception, tb, request: Request
    ):
        """
        Callback when sending order caused exception.
        """
        self.gateway.write_log(f"on_send_order_error {exception_value} {request.response.text}")
        orders = request.extra
        for order in orders:
            order.status = Status.REJECTED
            #align srv orderId
            self.on_error_recover_orderId(request)
            self.gateway.on_order(order)

        # Record exception if not ConnectionError
        if not issubclass(exception_type, ConnectionError):
            self.on_error(exception_type, exception_value, tb, request)
        else:
            # delay 150ms to avoid high TPS in srv.
            sleep(0.15)

    def on_error_recover_orderId(self, request, newest_order_id: int = 0):
        # self.gateway.write_log(f"on_error_recover_orderId: {request} {newest_order_id}")
        order_detail = ujson.loads(request.data)
        orderId = order_detail.get('storageId', None)
        tokenSId = order_detail.get("sellToken", {}).get("tokenId", None)
        if orderId is not None and tokenSId is not None:
            if newest_order_id != 0:
                self.orderId_manager.put_orderId(tokenSId, newest_order_id)
                # self.gateway.write_log(f"on_error_recover_orderId: updated orderid of {tokenSId} to {newest_order_id}")
            else:
                # self.gateway.write_log(f"on_error_recover_orderId: reuse orderId {orderId}")
                reuse_tokenS_orderIds = self.failed_orderId.get(tokenSId, [])
                reuse_tokenS_orderIds.append(orderId)
                self.failed_orderId[tokenSId] = reuse_tokenS_orderIds
        else:
            self.gateway.write_log(f"ERROR: recover orderId from request = {request} failed.")

    def on_failed(self, status_code: int, request: Request):
        """
        Callback to handle request failed.
        """
        msg = f"Error: 请求 {request} 失败，状态码：{status_code}"
        self.gateway.write_log(msg)
        # delay 150ms to avoid high TPS in srv.
        sleep(0.15)

    def on_error(self, exception_type: type, exception_value: Exception, tb, request: Request):
        """
        Callback to handler request exception.
        """
        msg = f"Error: 触发异常，状态码：{exception_type}，信息：{exception_value}"
        self.gateway.write_log(msg)

        sys.stderr.write(
            self.exception_detail(exception_type, exception_value, tb, request)
        )
        # delay 150ms to avoid high TPS in srv.
        sleep(0.15)

    def on_cancel_order(self, data, request):
        """"""
        self.gateway.write_log(f"Cancel order {request.data} 成功.")
        json_request = ujson.loads(request.data)
        if "clientOrderId" in json_request:
            clientOrderId = json_request['clientOrderId']
            if clientOrderId in self.gateway.orders:
                order = self.gateway.orders[clientOrderId]
                order.status = Status.CANCELLED
                self.gateway.on_order(order)

    def on_cancel_order_failed(self, status_code: int, request: Request):
        msg = f"on_cancel_order_fail {request.data} 失败，状态码：{status_code}"
        data = request.response.json()
        self.gateway.write_log(msg)
        cancelReq = ujson.loads(request.data)
        if 'clientOrderId' in cancelReq:
            for id in cancelReq['clientOrderId'].split(','):
                order = self.gateway.orders.get(id, None)
                if not order:
                    # self.gateway.write_log(f"Cancel Order, {id} not found in self order records")
                    pass
                else:
                    if "resultInfo" in data and "CANCELLED" in data['resultInfo']['message']:
                        order = self.gateway.orders[id]
                        order.status = Status.CANCELLED
                        hash = self.gateway.orderIdHashMap.get(id, None)
                        if not hash:
                            self.gateway.rest_api.query_order(hash)
                    elif "COMPLETELY_FILLED" in data['resultInfo']['message']:
                        order = self.gateway.orders[id]
                        order.status = Status.ALLTRADED
                        order.traded = order.volume
                        self.gateway.on_order(order)
                    else:
                        order.status = Status.CANCEL_REJECT
                        # tell engine this is a error
                        self.gateway.on_order(order)
        # delay 150ms to avoid high TPS in srv.
        sleep(0.5)
        pass

    def on_cancel_order_error(
            self, exception_type: type, exception_value: Exception, tb, request: Request
    ):
        """
        Callback when sending order caused exception.
        """
        self.gateway.write_log(f"on_cancel_order_error {exception_value} {request}")
        cancelReq = ujson.loads(request.data)
        if 'clientOrderId' in cancelReq:
            for id in cancelReq['clientOrderId'].split(','):
                order = self.gateway.orders.get(id, None)
                if not order:
                    self.gateway.write_log(f"Cancel Order, {id} not found in self order records")
                else:
                    order.status = Status.CANCEL_REJECT
                    # tell engine this is a error
                    self.gateway.on_order(order)

        # Record exception if not ConnectionError
        if not issubclass(exception_type, ConnectionError):
            self.on_error(exception_type, exception_value, tb, request)
        else:
            # delay 150ms to avoid high TPS in srv.
            sleep(0.5)

    def on_keep_user_stream(self, data, request):
        """"""
        pass

    def get_storageId(self, tokenSId):
        """"""
        data = {
            "security": Security.API_KEY
        }

        self.add_request(
            "GET",
            path="/api/v3/storageId",
            callback=self.on_get_storageId,
            data=data,
            params = {
                "accountId": self.accountId,
                "sellTokenId" : tokenSId
            }
        )

    def query_history(self, req: HistoryRequest):
        """"""
        history = []
        limit = 1000
        start_time = int(datetime.timestamp(req.start))

        while True:
            # Create query params
            params = {
                "market": req.symbol,
                "interval": INTERVAL_VT2LOOPRING[req.interval],
                "limit": limit,
                "start": start_time * 1000,  # convert to millisecond
            }

            # Add end time if specified
            if req.end:
                end_time = int(datetime.timestamp(req.end))
                params["end"] = end_time * 1000  # convert to millisecond

            # Get response from server
            resp = self.request(
                "GET",
                "/api/v3/candlestick",
                data={"security": Security.NONE},
                params=params
            )

            # Break if request failed with other status code
            if resp.status_code // 100 != 2:
                msg = f"Error: 获取历史数据失败，状态码：{resp.status_code}，信息：{resp.text}"
                self.gateway.write_log(msg)
                break
            else:
                data = resp.json()
                if not data:
                    msg = f"Error: 获取历史数据为空，开始时间：{start_time}"
                    self.gateway.write_log(msg)
                    break

                buf = []

                for l in data['data']:
                    #[开始时间，交易笔数，开盘价，收盘价，最高价，最低价，Base Token成交总量，Quote Token成交总额]
                    dt = datetime.fromtimestamp(l[0] / 1000)  # convert to second

                    bar = BarData(
                        symbol=req.symbol,
                        exchange=req.exchange,
                        datetime=dt,
                        interval=req.interval,
                        volume=float(l[6]),
                        open_price=float(l[2]),
                        high_price=float(l[4]),
                        low_price=float(l[5]),
                        close_price=float(l[3]),
                        gateway_name=self.gateway_name
                    )
                    buf.append(bar)

                history.extend(buf)

                begin = buf[0].datetime
                end = buf[-1].datetime
                msg = f"获取历史数据成功，{req.symbol} - {req.interval.value}，{begin} - {end}"
                self.gateway.write_log(msg)

                # Break if total data count less than limit (latest date collected)
                if len(data) < limit:
                    break

                # Update start time
                start_dt = bar.datetime + TIMEDELTA_MAP[req.interval]
                start_time = int(datetime.timestamp(start_dt))

        return history

    def reset_loopring_connection(self):
        repeat_try = 0
        while True:
            try:
                repeat_try += 1
                wsApiKey = self.gateway.query_ws_key()
                return WEBSOCKET_TRADE_HOST + "?" + urllib.parse.urlencode({"wsApiKey": wsApiKey}, safe=',')
            except:
                if repeat_try % 10 == 0:
                    self.gateway.write_log(f"try query_ws_key {repeat_try} times.")
                sleep(5)

# Tracking own trades
class LoopringTradeWebsocketApi(WebsocketClient):
    """"""

    def __init__(self, gateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name
        self.subscribe_reqs = {}
        self.last_subscribe_reqs = {}
        self.ping_interval = 60*60*24*365 #hardcode 1 year, which means never send ping as we send ping in our own pace
        self.account_sub = False

    def connect(self, url, proxy_host, proxy_port):
        """"""
        url = self.gateway.reset_loopring_connection()
        self.init(url, proxy_host, proxy_port)
        self.start()

    def on_disconnected(self):
        """"""
        self.gateway.write_log(f"交易Websocket API连接断开: subscribed reqs = {self.subscribe_reqs}")
        self.last_subscribe_reqs.update(self.subscribe_reqs)
        self.subscribe_reqs.clear()
        self.account_sub = False
        sleep(5) # sleep 2s to avoid srv refuse connection
        self.host = self.gateway.reset_loopring_connection()

    def on_connected(self):
        """"""
        self.gateway.write_log(f"交易Websocket API连接成功: subscribed reqs = {self.last_subscribe_reqs}")
        # self.gateway.rest_api.query_orders()
        for req in self.last_subscribe_reqs.values():
            self.subscribe(req)
        self.gateway.rest_api.query_balance()

    def subscribe(self, req: SubscribeRequest):
        # subscribe
        self.gateway.write_log(f"交易Websocket API连接 subscribe {req} after {self.subscribe_reqs}")
        channels = {
            "op": "sub",
            "sequence": 10000,
            "apiKey": self.gateway.rest_api.key,
            "unsubscribeAll": False, #last account sub works
            "topics": [
                {
                    "topic": "account"
                }
            ]
        }
        self.account_sub = True
        self.send_packet(channels)

        channels = {
            "op": "sub",
            "sequence": 20000 + len(self.subscribe_reqs),
            "apiKey": self.gateway.rest_api.key,
            "unsubscribeAll": False, #keep previous sub
            "topics": [
                {
                    "topic": "order",
                    "market": req.symbol
                }
            ]
        }
        self.subscribe_reqs[req.symbol] = req
        self.send_packet(channels)

    def on_packet(self, packet):  # type: (dict)->None
        # self.gateway.write_log(f"交易on_packet {packet}")
        """"""
        if "ping" in packet:
            self._send_text("pong")
            return

        jsonData = packet #ujson.loads(ujson.dumps(eval(str(packet))))
        if 'result' in jsonData:
            result = jsonData['result']
            status = result['status']
            if status != 'OK':
                self.gateway.write_log("LoopringDEX trade WS Error status:" + status)
                raise ConnectionError(f"{result}")

        if "topic" in jsonData:
            topic = jsonData['topic']['topic']
            if topic == "account":
                self.on_account(jsonData)
            elif topic == "order":
                self.on_order(jsonData)

    def on_account(self, packet):
        # self.gateway.write_log(f"交易on_account {packet}")
        """"""
        d = packet["data"]
        for token in self.gateway.rest_api.tokens.keys():
            if self.gateway.rest_api.tokens[token].tokenId== d["tokenId"]:
                accountId = self.gateway.rest_api.tokens[token].symbol
                decimal = self.gateway.rest_api.tokens[token].decimals
                account = AccountData(
                    accountid=accountId,
                    balance=float(d["totalAmount"])/(10**decimal),
                    frozen=float(d["amountLocked"])/(10**decimal),
                    gateway_name=self.gateway_name
                )

                if account.balance:
                    self.gateway.on_account(account)

    def on_order(self, packet):
        # self.gateway.write_log(f"交易on_order {packet}")
        """"""
        # dt = datetime.fromtimestamp(packet["ts"] / 1000)
        # time = dt.strftime("%Y-%m-%d %H:%M:%S")

        data = packet["data"]
        market = data['market']
        orderid = data["clientOrderId"]
        hash = data["hash"]
        decimals = self.gateway.rest_api.contracts[market].decimals
        status = data["status"]
        if status == "processing" and "filledSize" in data and int(data['filledSize']) > 0:
            status = "filled"

        order = OrderData(
            symbol=market,
            exchange=Exchange.LOOPRINGV36,
            orderid=orderid,
            direction=DIRECTION_LOOPRING2VT[data["side"]],
            price=float(data["price"]),
            volume=float(data["size"])/(10**decimals),    # TODO: decimals
            traded=float(data["filledSize"])/(10**decimals),
            status=STATUS_LOOPRING2VT[status],
            datetime=datetime.fromtimestamp(float(packet["ts"]) / 1000).__str__(),
            gateway_name=self.gateway_name
        )
        previous_traded = 0
        previous_order_status = self.gateway.orders.get(order.orderid, None)
        if previous_order_status:
            previous_traded = previous_order_status.traded
        self.gateway.on_order(order, hash)

        order_traded = order.traded - previous_traded
        if order_traded > 0:
            trade = TradeData(
                symbol=market,
                exchange=Exchange.LOOPRING,
                orderid=order.orderid,
                tradeid=order.orderid,
                direction=order.direction,
                price=order.price,
                volume=order_traded,
                datetime=order.datetime,
                gateway_name=self.gateway_name,
            )
            self.gateway.on_trade(trade)

    @staticmethod
    def unpack_data(data: str):
        """
        Default serialization format is json.

        override this method if you want to use other serialization format.
        """
        if "ping" == data:
            return {"ping":"pong"}
        return ujson.loads(data)

class LoopringDataWebsocketApi(WebsocketClient):
    """"""

    def __init__(self, gateway):
        """"""
        super().__init__()

        self.gateway = gateway
        self.gateway_name = gateway.gateway_name
        self.ping_interval = 60*60*24*365 #hardcode 1 year, which means never send ping as we send ping in our own pace

        self.ticks = {}
        self.last_tick_timestampe = 0
        self.last_packet_timestampe = 0
        self.subscribe_reqs = {}
        self.last_subscribe_reqs = {}

    def connect(self, proxy_host: str, proxy_port: int):
        """"""
        self.gateway.write_log("行情Websocket API开始connect")
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

        url = self.gateway.reset_loopring_connection()
        self.init(url, self.proxy_host, self.proxy_port)
        self.start()

    def on_disconnected(self):
        """"""
        self.gateway.write_log(f"行情Websocket API连接断开: subscribed reqs = {self.subscribe_reqs}")
        self.last_subscribe_reqs.update(self.subscribe_reqs)
        self.subscribe_reqs.clear()
        sleep(5) # sleep 5s to avoid srv refuse new connection
        self.host = self.gateway.reset_loopring_connection()

    def on_connected(self):
        """"""
        self.gateway.write_log(f"行情Websocket API连接刷新: subscribed reqs = {self.last_subscribe_reqs}")
        for req in self.last_subscribe_reqs.values():
            self.subscribe(req)

    def subscribe(self, req: SubscribeRequest):
        self.gateway.write_log(f"行情Websocket subscribe {req} after {self.subscribe_reqs}")
        """"""

        if req.symbol not in symbol_name_map:
            self.gateway.write_log(f"找不到该合约代码{req.symbol}")
            return

        if req.symbol in self.subscribe_reqs:
            self.gateway.write_log(f"已经订阅了合约代码{req.symbol}")
            return

        # Create tick buf data
        tick = self.ticks.get(req.symbol.upper(), TickData(symbol=req.symbol,
                                                           name=symbol_name_map.get(req.symbol, ""),
                                                           exchange=Exchange.LOOPRINGV36,
                                                           datetime=datetime.now(),
                                                           gateway_name=self.gateway_name))
        self.ticks[req.symbol.upper()] = tick
        self.subscribe_reqs[req.symbol] = req

        subscribe_args = []
        subscribe_args.append(
            {
                "topic"  : "orderbook",
                "market" : req.symbol,
                "level": 0,
                "count": 10,
                "snapshot" : True,
            }
        )

        # Create new connection
        channels = {
            "op": "sub",
            "sequence": 30000 + len(self.subscribe_reqs),
            "unsubscribeAll": False,
            "topics": subscribe_args
        }

        self.send_packet(channels)

    def on_packet(self, packet):
        # self.gateway.write_log(f"行情on_packet {packet}")
        if "ping" in packet:
            self.gateway.write_log("行情send_pong")
            self._send_text("pong")
            return

        # jsonData = ujson.loads(ujson.dumps(eval(str(packet))))
        jsonData = packet
        # subscribe status code
        if 'result' in jsonData:
            result = jsonData['result']
            status = result['status']
            if status != 'OK':
                self.gateway.write_log("LoopringDEX data WS Error status:" + status)
                raise ConnectionError(f"{result}")

        # real data streaming
        if 'topic' in jsonData:
            topics = jsonData['topic']
            if topics['topic'] == "trade":
                # "topics": { "topic": "trade", "market": "LRC-ETH" },
                # "ts": 1584717910000,
                # "data": [
                #     [
                #         "1584717910000",  //timestamp
                #         "123456789",  //tradeId
                #         "buy",  //side
                #         "500000",  //size 
                #         "0.0008",  //price
                #         "100"  //fee
                #     ]
                # ]
                # trade data
                market = topics['market']
                datas = jsonData['data']
                for data in datas:
                    order_direction = Direction.LONG
                    if data[2] == 'sell':
                        order_direction = Direction.SHORT

                    decimals = self.gateway.rest_api.contracts[market].decimals
                    trade_dt = datetime.fromtimestamp(float(data[0]) / 1000)
                    trade_time = trade_dt.strftime("%Y-%m-%d %H:%M:%S.%f")
                    trade = TradeData(
                        symbol=market,
                        exchange=Exchange.LOOPRINGV36,
                        orderid=data[1],
                        tradeid=data[1],
                        direction=order_direction,
                        price=data[4],
                        volume=float(data[3])/(10**decimals),   # TODO: decimal
                        time=trade_time,
                        gateway_name=self.gateway_name,
                    )
                    self.gateway.on_trade(trade)
            elif topics['topic'] == "candlestick":
                # {'topic': 'ticker&lrc-eth', 'ts': 1574150830158,
                #  'data': {'count': '2', 'timestamp': '1574150830158', 'size': '37600000000000000', 'last': '0.000188',
                #           'open': '0.000188', 'low': '0.000188', 'ask': '0.000189', 'bid': '0.000020', 'high': '0.000188'}}
                market = topics['market']
                decimals = self.gateway.rest_api.contracts[market].decimals
                data = jsonData['data']
                tick = self.ticks[market]
                tick.market = market
                tick.last_volume = tick.volume
                tick.volume = float(data[6])/(10**decimals)    # TODO: decimal
                tick.open_price = float(data[2])
                tick.high_price = float(data[4])
                tick.low_price = float(data[5])
                tick.last_price = float(data[3])
                tick.datetime = datetime.fromtimestamp(float(jsonData['ts']) / 1000)
                # if tick.bid_volume_1 > 0 or tick.ask_volume_1 > 0:
                #     self.gateway.on_tick(copy(tick))

                # TODO: when reset tick volume?
            elif topics['topic'] == "orderbook":
                '''
                "topic": {
                    "topic:": "orderbook",
                    "market": "LRC-USDT",
                    "level": 0,
                    "count": 20,
                    "snapshot": true
                },
                "ts": 1584717910000,
                "startVersion": 1212121,
                "endVersion": "1212123",
                "data": {
                    "bids": [
                        [
                            "295.97",  //price
                            "456781000000000",  //size
                            "3015000000000",  //volume
                            "4"  //count
                        ]
                    ],
                    "asks": [
                        [
                        "298.97",
                        "456781000000000000",
                        "301500000000000",
                        "2"
                        ]
                    ]
                }
                '''
                # depth data
                market = topics['market'].upper()
                data = jsonData['data']

                bids = data['bids']
                asks = data['asks']

                decimals = self.gateway.rest_api.contracts[market].decimals
                tick = self.ticks[market]
                # re-init entries, for now loopring does not need to support >5 depth
                # tricky: bid is ascend sorted, somehow counter-intuition.
                if len(bids) > 0:
                    for n in range(len(bids), 0, -1):
                        price = bids[n-1][0]
                        volume = int(bids[n-1][1])/(10**decimals)
                        tick.__setattr__("bid_price_" + str(n), float(price))
                        tick.__setattr__("bid_volume_" + str(n), float(volume))

                if len(asks) > 0:
                    for n in range(len(asks)):
                        price = asks[n][0]
                        volume = int(asks[n][1])/(10**decimals)
                        tick.__setattr__("ask_price_" + str(n + 1), float(price))
                        tick.__setattr__("ask_volume_" + str(n + 1), float(volume))

                packet_timestampe = jsonData['ts'] / 1000 # in s
                current_timestamp = time.time()

                self.last_packet_timestampe = packet_timestampe
                self.last_tick_timestampe = current_timestamp
                tick.datetime = datetime.fromtimestamp(packet_timestampe)
                self.gateway.on_tick(copy(tick))

    @staticmethod
    def unpack_data(data: str):
        """
        Default serialization format is json.

        override this method if you want to use other serialization format.
        """
        if "ping" == data:
            return data
        return ujson.loads(data)
