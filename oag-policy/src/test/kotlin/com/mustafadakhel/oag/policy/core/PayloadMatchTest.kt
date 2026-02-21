package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.policy.evaluation.evaluatePolicyWithRule

import kotlin.test.Test
import kotlin.test.assertEquals

class PayloadMatchTest {

    private fun request(host: String = "api.example.com", path: String = "/graphql", payload: StructuredPayload? = null) =
        PolicyRequest(
            scheme = "https",
            host = host,
            port = 443,
            method = "POST",
            path = path,
            structuredPayload = payload
        )

    @Test
    fun `rule with jsonrpc payload match allows matching request`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-mcp",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "jsonrpc", method = "tools/call")
                    )
                )
            )
        )
        val payload = StructuredPayload(
            protocol = DetectedProtocol.JSON_RPC,
            method = "tools/call",
            id = "1"
        )
        val result = evaluatePolicyWithRule(policy, request(payload = payload))
        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("allow-mcp", result.decision.ruleId)
    }

    @Test
    fun `rule with graphql payload match allows matching request`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-graphql",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "graphql", operationType = "query")
                    )
                )
            )
        )
        val payload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationName = "GetUsers",
            operationType = GraphQlOperationType.QUERY
        )
        val result = evaluatePolicyWithRule(policy, request(payload = payload))
        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("allow-graphql", result.decision.ruleId)
    }

    @Test
    fun `rule with payload match does not match when no structured payload in request`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-mcp",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "jsonrpc", method = "tools/call")
                    )
                )
            )
        )
        val result = evaluatePolicyWithRule(policy, request(payload = null))
        assertEquals(PolicyAction.DENY, result.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, result.decision.reasonCode)
    }

    @Test
    fun `rule without payload match matches regardless of structured payload`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(id = "allow-all", host = "*.example.com")
            )
        )
        val payload = StructuredPayload(
            protocol = DetectedProtocol.JSON_RPC,
            method = "tools/call"
        )
        val result = evaluatePolicyWithRule(policy, request(payload = payload))
        assertEquals(PolicyAction.ALLOW, result.decision.action)
        assertEquals("allow-all", result.decision.ruleId)
    }

    @Test
    fun `graphql mutation payload match only matches mutation`() {
        val policy = PolicyDocument(
            deny = listOf(
                PolicyRule(
                    id = "deny-mutations",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "graphql", operationType = "mutation")
                    )
                )
            ),
            allow = listOf(
                PolicyRule(id = "allow-all", host = "*.example.com")
            )
        )

        val queryPayload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationType = GraphQlOperationType.QUERY
        )
        val queryResult = evaluatePolicyWithRule(policy, request(payload = queryPayload))
        assertEquals(PolicyAction.ALLOW, queryResult.decision.action)

        val mutationPayload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationType = GraphQlOperationType.MUTATION
        )
        val mutationResult = evaluatePolicyWithRule(policy, request(payload = mutationPayload))
        assertEquals(PolicyAction.DENY, mutationResult.decision.action)
        assertEquals("deny-mutations", mutationResult.decision.ruleId)
    }

    @Test
    fun `payload match with operation name regex`() {
        val policy = PolicyDocument(
            deny = listOf(
                PolicyRule(
                    id = "deny-delete-ops",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "graphql", operation = "Delete.*")
                    )
                )
            ),
            allow = listOf(
                PolicyRule(id = "allow-all", host = "*.example.com")
            )
        )

        val createPayload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationName = "CreateUser",
            operationType = GraphQlOperationType.MUTATION
        )
        val createResult = evaluatePolicyWithRule(policy, request(payload = createPayload))
        assertEquals(PolicyAction.ALLOW, createResult.decision.action)

        val deletePayload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationName = "DeleteUser",
            operationType = GraphQlOperationType.MUTATION
        )
        val deleteResult = evaluatePolicyWithRule(policy, request(payload = deletePayload))
        assertEquals(PolicyAction.DENY, deleteResult.decision.action)
    }

    @Test
    fun `payload match with jsonrpc method regex`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-tools",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "jsonrpc", method = "tools/.*")
                    )
                )
            )
        )

        val matchPayload = StructuredPayload(
            protocol = DetectedProtocol.JSON_RPC,
            method = "tools/list",
            id = "1"
        )
        val result = evaluatePolicyWithRule(policy, request(payload = matchPayload))
        assertEquals(PolicyAction.ALLOW, result.decision.action)

        val noMatchPayload = StructuredPayload(
            protocol = DetectedProtocol.JSON_RPC,
            method = "resources/list",
            id = "2"
        )
        val result2 = evaluatePolicyWithRule(policy, request(payload = noMatchPayload))
        assertEquals(PolicyAction.DENY, result2.decision.action)
    }

    @Test
    fun `unknown protocol in rule does not match and request is denied`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-grpc",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "grpc", method = "SayHello")
                    )
                )
            )
        )
        val payload = StructuredPayload(
            protocol = DetectedProtocol.JSON_RPC,
            method = "SayHello",
            id = "1"
        )
        val result = evaluatePolicyWithRule(policy, request(payload = payload))
        assertEquals(PolicyAction.DENY, result.decision.action)
        assertEquals(ReasonCode.NO_MATCH_DEFAULT_DENY, result.decision.reasonCode)
    }

    @Test
    fun `wrong protocol does not match`() {
        val policy = PolicyDocument(
            allow = listOf(
                PolicyRule(
                    id = "allow-jsonrpc",
                    host = "*.example.com",
                    payloadMatch = listOf(
                        PolicyPayloadMatch(protocol = "jsonrpc", method = "tools/call")
                    )
                )
            )
        )
        val graphqlPayload = StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationName = "tools/call"
        )
        val result = evaluatePolicyWithRule(policy, request(payload = graphqlPayload))
        assertEquals(PolicyAction.DENY, result.decision.action)
    }
}
