package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.StageSet

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConnectTrafficUnitTest {

    @Test
    fun `connect stage set includes identity target policy actions`() {
        assertTrue(PipelineStage.IDENTITY in StageSet.CONNECT)
        assertTrue(PipelineStage.TARGET in StageSet.CONNECT)
        assertTrue(PipelineStage.POLICY in StageSet.CONNECT)
        assertTrue(PipelineStage.ACTIONS in StageSet.CONNECT)
    }

    @Test
    fun `connect stage set excludes inspect`() {
        assertTrue(PipelineStage.INSPECT !in StageSet.CONNECT)
    }

    @Test
    fun `filterByStageSet filters phases by stage membership`() {
        val identityPhase = object : Phase {
            override val name = "test_identity"
            override val stage = PipelineStage.IDENTITY
            override suspend fun execute(context: RequestPipelineContext) {}
        }
        val targetPhase = object : Phase {
            override val name = "test_target"
            override val stage = PipelineStage.TARGET
            override suspend fun execute(context: RequestPipelineContext) {}
        }
        val inspectPhase = object : Phase {
            override val name = "test_inspect"
            override val stage = PipelineStage.INSPECT
            override suspend fun execute(context: RequestPipelineContext) {}
        }

        val pipeline = Pipeline(name = "test", phases = listOf(identityPhase, targetPhase, inspectPhase))
        val connectPipeline = pipeline.filterByStageSet(StageSet.CONNECT)

        assertEquals(2, connectPipeline.phaseCount)
        assertEquals(listOf("test_identity", "test_target"), connectPipeline.phaseNames())
    }

    @Test
    fun `filterByStageSet with ALL returns all phases`() {
        val phases = listOf(
            object : Phase {
                override val name = "a"
                override val stage = PipelineStage.IDENTITY
                override suspend fun execute(context: RequestPipelineContext) {}
            },
            object : Phase {
                override val name = "b"
                override val stage = PipelineStage.INSPECT
                override suspend fun execute(context: RequestPipelineContext) {}
            }
        )
        val pipeline = Pipeline(name = "test", phases = phases)
        assertEquals(2, pipeline.filterByStageSet(StageSet.ALL).phaseCount)
    }
}
