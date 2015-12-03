package org.g4.certificate.checker;

import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PropsRuleCheckerTest {
	
	@Before
    public void setUp() throws Exception {
    }
	
    @After
    public void tearDown() throws Exception {
    } 
    
 // test normal scenario  
    @Test
    public void testValidateKeyWordsNomal()
    {
    	// preapare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	String[] keyWords = new String[]{"key1", "key2"};
    	paramMap.put("key1", "not null value");
    	paramMap.put("key2", "not null value");
    	boolean result = PropsRuleChecker.validateKeyWords(paramMap, keyWords);
    	
    	assertTrue(result);

    }
    
    
 // test abnormal scenario  
    @Test
    public void testValidateKeyWordsAbnomal()
    {
    	// preapare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	String[] keyWords = new String[]{"key1", "key2"};
    	paramMap.put("key1", "not null value");
    	boolean result = PropsRuleChecker.validateKeyWords(paramMap, keyWords);
    	
    	assertFalse(result);

    }
    
    
    // test normal scenario  
    @Test
    public void testIsDuplicated()
    {
    	String[] testArr = new String[]{"aaa", "bbb", "ccc"};
    	boolean result = CertUtil.isDuplicated(testArr);
    	
    	assertFalse(result);
    	
    	testArr = new String[]{"aaa", "bbb", "aaa"};
    	result = CertUtil.isDuplicated(testArr);
    	
    	assertTrue(result);
    }
    
    
 // test isNull()  
    @Test
    public void testIsNull()
    {
    	Map<String, String> testMap = new HashMap<String, String>();
    	testMap.put("notNullValueKey", "notNullValue");
    	boolean result = PropsRuleChecker.isNull(testMap, "notNullValueKey", null);
    	assertFalse(result);
    	
    	testMap.put("nullValueKey", null);
    	result = PropsRuleChecker.isNull(testMap, "nullValueKey", null);
    	assertTrue(result);
    	
    }
    
    
    // test isValidDName()  
    @Test
    public void testIsValidDNameNormal()
    {
    	// prepare test data
    	String prefix = "testPrefix";
    	Map<String, String> testMap = new HashMap<String, String>();
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_OU, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_O, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_L, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_ST, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_C, "not null value");
    	boolean result = PropsRuleChecker.isValidDName(testMap, prefix);
    	
    	assertTrue(result);
    	
    }
    
    // test : no enough parameter passed, some parameter is null value
    @Test
    public void testIsValidDNameAbnormal()
    {
    	// prepare test data
    	String prefix = "testPrefix";
    	Map<String, String> testMap = new HashMap<String, String>();
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_OU, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_O, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_L, "not null value");
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_ST, "not null value");

    	// test when lost CertParamTemplate.PARAMETER_DNAME_C
    	boolean result = PropsRuleChecker.isValidDName(testMap, prefix);
    	
    	assertFalse(result);
    	
    	// contained all parameters, but value is null
    	testMap.put(prefix +"." + CertParamTemplate.PARAMETER_DNAME_C, null);
    	
    	assertFalse(result);
    	
    }
    
    // test no null and duplicated value
    @Test
    public void testValidateNullAndDuplicatedNormal()
    {
    	// prepare test data
    	String singleValueKey = "sigleeValueKey";
    	String multipeValueKey = "multipleValueKey";
    	String commaEndedKey = "commaEndedKey";
    	Map<String, String> testMap = new HashMap<String, String>();
    	testMap.put(singleValueKey, "singleValue");
    	testMap.put(multipeValueKey, "singleValue,multipleValue");
    	testMap.put(commaEndedKey, "singleValue,,,multipleValue,");
    	// test single value
    	boolean  result = PropsRuleChecker.validateNullAndDuplicated(testMap, singleValueKey);
    	
    	assertTrue(result);
    	
    	// test multiple value seperated by ","
    	result = PropsRuleChecker.validateNullAndDuplicated(testMap, singleValueKey);
    	assertTrue(result);
    	
    	// test when comma ended
    	result = PropsRuleChecker.validateNullAndDuplicated(testMap, commaEndedKey);
    	assertFalse(result);
    	
    }
    
    // test null or duplicated value
    @Test
    public void testValidateNullAndDuplicatedAbnormal()
    {
    	// prepare test data
    	String nullValueKey = "nullValueKey";
    	String duplicateValueKey = "duplicateValueKey";
    	
    	Map<String, String> testMap = new HashMap<String, String>();
    	testMap.put(nullValueKey, null);
    	testMap.put(duplicateValueKey, "value1,value2,value1");
    	
    	// test null value
    	boolean  result = PropsRuleChecker.validateNullAndDuplicated(testMap, nullValueKey);
    	
    	assertFalse(result);
    	
    	// test duplicate value seperated by ","
    	result = PropsRuleChecker.validateNullAndDuplicated(testMap, duplicateValueKey);
    	assertFalse(result);
    	
    }
    
    
 // test null or duplicated value
    @Test
    public void testValidateNull4ChildItemsNormal()
    {
    	// prepare test data
    	String key = "server.list";
    	String prefix = "server";
    	String[] suffixArray = new String[]{"fqdn"};
    	
    	Map<String, String> paramMap = new HashMap<String, String>();
    	paramMap.put(key, "loadbalancer,server1");
    	paramMap.put("server.server1.fqdn", "server1");
    	paramMap.put("server.loadbalancer.fqdn", "loadbalancer");
    	
    	boolean  result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
    	
    	assertTrue(result);

        //duplicated values
        paramMap.clear();
        paramMap.put(key, "loadbalancer,server1");
        paramMap.put("server.server1.fqdn", "server1");
        paramMap.put("server.loadbalancer.fqdn", "server1");
        result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
        assertFalse(result);
    }
    
 // test null or duplicated value
    @Test
    public void testValidateNull4ChildItemsAbnormal()
    {
    	// prepare test data
    	String key = "server.list";
    	String prefix = "server";
    	String[] suffixArray = new String[]{"fqdn"};
    	
    	Map<String, String> paramMap = new HashMap<String, String>();
    	paramMap.put(key, "loadbalancer,server1");
    	paramMap.put("server.server1.fqdn", "not null value");

    	// value is configured but not sub item defined.
    	boolean  result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
    	
    	assertFalse(result);
    	
    	// sub item with null value
    	paramMap.put("server.loadbalancer.fqdn", null);
    	result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
    	
    	assertFalse(result);
    	
    	// key contained null value
    	paramMap.put(key, ",loadbalancer,,server1,");
    	paramMap.put("server.loadbalancer.fqdn", "not null value");
    	result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
    	
    	assertFalse(result);
    	
    	// key contains space
    	paramMap.put(key, " loadbalancer, , server1");
    	result = PropsRuleChecker.validateNullAndDuplicated4ChildItems(paramMap, key, prefix, suffixArray);
    	
    	assertFalse(result);
    }
    
    
}
