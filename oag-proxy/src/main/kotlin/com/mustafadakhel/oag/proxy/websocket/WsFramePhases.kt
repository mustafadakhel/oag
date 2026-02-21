package com.mustafadakhel.oag.proxy.websocket

import com.mustafadakhel.oag.TrafficUnit

internal fun WebSocketFrame.toTrafficUnit() =
    TrafficUnit.WsFrame(
        text = if (isText) textPayload else "",
        isText = isText
    )
