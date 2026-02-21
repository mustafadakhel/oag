package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PipelineStageTest {

    @Test
    fun `pipeline stage has 5 entries`() {
        assertEquals(5, PipelineStage.entries.size)
    }

    @Test
    fun `label returns lowercase name`() {
        assertEquals("identity", PipelineStage.IDENTITY.label())
        assertEquals("target", PipelineStage.TARGET.label())
        assertEquals("policy", PipelineStage.POLICY.label())
        assertEquals("inspect", PipelineStage.INSPECT.label())
        assertEquals("actions", PipelineStage.ACTIONS.label())
    }

    @Test
    fun `ALL stage set contains every stage`() {
        for (stage in PipelineStage.entries) {
            assertTrue(stage in StageSet.ALL, "ALL should contain $stage")
        }
    }

    @Test
    fun `REQUEST stage set contains all 5 stages`() {
        assertEquals(5, StageSet.REQUEST.stages.size)
    }

    @Test
    fun `CONNECT stage set skips inspect`() {
        assertTrue(PipelineStage.IDENTITY in StageSet.CONNECT)
        assertTrue(PipelineStage.POLICY in StageSet.CONNECT)
        assertTrue(PipelineStage.ACTIONS in StageSet.CONNECT)
        assertFalse(PipelineStage.INSPECT in StageSet.CONNECT)
    }
}
