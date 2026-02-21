package com.mustafadakhel.oag.inspection

import kotlin.test.Test
import kotlin.test.assertIs

class InspectableArtifactTest {

    @Test
    fun `TextBody is an InspectableArtifact`() {
        val artifact: InspectableArtifact = TextBody("hello")
        assertIs<TextBody>(artifact)
    }

    @Test
    fun `Headers is an InspectableArtifact`() {
        val artifact: InspectableArtifact = Headers(listOf(HeaderEntry("Host", "example.com")))
        assertIs<Headers>(artifact)
    }

    @Test
    fun `Url is an InspectableArtifact`() {
        val artifact: InspectableArtifact = Url("https", "example.com", 443, "/api", "q=1")
        assertIs<Url>(artifact)
    }

    @Test
    fun `DnsLabel is an InspectableArtifact`() {
        val artifact: InspectableArtifact = DnsLabel("data.exfil.example.com")
        assertIs<DnsLabel>(artifact)
    }

    @Test
    fun `WsFrame is an InspectableArtifact`() {
        val artifact: InspectableArtifact = WsFrame("payload", isText = true)
        assertIs<WsFrame>(artifact)
    }

    @Test
    fun `sealed hierarchy is exhaustive in when`() {
        val artifacts: List<InspectableArtifact> = listOf(
            TextBody("body"),
            Headers(emptyList()),
            Url("https", "h", 443, "/", null),
            DnsLabel("l"),
            ResponseTextBody("body", 200, "text/plain"),
            WsFrame("f", true),
            StreamingResponseBody("accumulated", 200, "text/event-stream", false)
        )
        artifacts.forEach { artifact ->
            val label = when (artifact) {
                is TextBody -> "text"
                is Headers -> "headers"
                is Url -> "url"
                is DnsLabel -> "dns"
                is ResponseTextBody -> "response_text"
                is WsFrame -> "ws"
                is StreamingResponseBody -> "streaming_response"
            }
            assert(label.isNotEmpty())
        }
    }
}
