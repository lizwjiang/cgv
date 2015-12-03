package org.g4.certificate.parser.gen;

import org.g4.certificate.parser.TSOGenParamParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TSOGenParamParserTest {
    private TSOGenParamParser tsoPH = null;

    @Before
    public void setUp() throws Exception {
        tsoPH = new TSOGenParamParser(); // tested class
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testAnalyzeParams4Test() {
        String[] parameters = new String[]{"-tso", "-t"};
        boolean result = tsoPH.analyzeParams(parameters);
        assertTrue(result);
        assertTrue(tsoPH.isTest());
    }

    @Test
    public void testAnalyzeParamsWithIllegalParam() {
        // -abc is illegal parameter
        String[] parameters = new String[]{"-tso", "-t", "-abc"};
        boolean result = tsoPH.analyzeParams(parameters);
        assertFalse(result);

        // abc is illegal parameter
        parameters = new String[]{"-tso", "-t", "abc"};
        result = tsoPH.analyzeParams(parameters);
        assertFalse(result);


        parameters = new String[]{"-tso", "abc"};
        result = tsoPH.analyzeParams(parameters);
        assertFalse(result);
    }

}
