package org.g4.certificate.checker;

import org.g4.certificate.utilities.CertParamTemplate;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TSOPropsRuleCheckerTest {
	
	@Before
    public void setUp() throws Exception {
    }
	
    @After
    public void tearDown() throws Exception {
    } 
    
    // test normal scenario
    @Test
    public void testValidaterNormal()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// below keywords should be provided and loadbalnacer should be in server list
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    	
    	// fqdn for server/client should exist
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + ".server1." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "server1");
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + "."+ CertParamTemplate.PARAMETER_LOADBALANCER + "." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "server2");
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_CLIENT + ".client1." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "client1");

    	// dname should exist
    	prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_GLOBAL);
    	
    	boolean result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertTrue(result);
    }
    
    
    // test abnormal scenario for key word
    @Test
    public void testValidaterAbnormalForKeyWord()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// lost key word:  server.list
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    
    	
    	boolean result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    	
    	// lost key word:  client.list
    	paramMap.clear(); 
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    
    	
    	result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    	
    	// lost key word:  dntype
    	paramMap.clear(); 
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
       	result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    	
    	// lost key word:  cn.common.name
    	paramMap.clear(); 
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));  	
    	result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    }
    
 // test abnormal scenario for loadbalancer
    @Test
    public void testValidaterAbnormalForLB()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	//  loadbalnacer is not in server list
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    	
    	boolean result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);    	
    }
    
    // test abnormal scenario for fqdn
    @Test
    public void testValidaterAbnormalForFQDN()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// below keywords should be provided and loadbalnacer should be in server list
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    	
    	// fqdn for server/client should exist
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + ".server1." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "not null value");
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + "."+ CertParamTemplate.PARAMETER_LOADBALANCER + "." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "not null value");
    	
    	
    	boolean result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    }
    
 // test abnormal scenario for dntype
    @Test
    public void testValidaterAbnormalForDNType()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// test illegal dntype to ensure dntype validation is invoked
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER + ",server1");
    	paramMap.put(CertParamTemplate.PARAMETER_CLIENT_LIST, "client1");
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	paramMap.put(CertParamTemplate.PARAMETER_CA_COMMON_NAME, "ca.common.name");
    	
    	// fqdn is not provided engough
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + ".server1." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "not null value");
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_SERVER + "."+ CertParamTemplate.PARAMETER_LOADBALANCER + "." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "not null value");
    	paramMap.put( CertParamTemplate.PARAMETER_PREFIX_CLIENT + ".client1." + CertParamTemplate.PARAMETER_SUFFIX_FQDN, "not null value");

    	
    	boolean result = TSOPropsRuleChecker.validate(paramMap);
    	
    	assertFalse(result);
    }
    
    
    
    // test normal scenario
    @Test
    public void testValidateLoadBalancerNormal()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, CertParamTemplate.PARAMETER_LOADBALANCER);
    	boolean result = TSOPropsRuleChecker.validateLoadBalancer(paramMap);
    	
    	assertTrue(result);
    }
    
    
    // test abnormal scenario
    @Test
    public void testValidateLoadBalancerabNormal()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, ",");
    	boolean result = TSOPropsRuleChecker.validateLoadBalancer(paramMap);
    	
    	assertFalse(result);
    	
    	paramMap.put(CertParamTemplate.PARAMETER_SERVER_LIST, "server2,server3");
    	result = TSOPropsRuleChecker.validateLoadBalancer(paramMap);
    	
    	assertFalse(result);
    }
    
    // test normal scenario
    @Test
    public void testValidateDNameNormal()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// set global type to global
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_GLOBAL);
    	boolean result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertTrue(result);
    	
    	// set global type to client&server
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENT_SERVER));
        prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT_SERVER);
        prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_CA);
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertTrue(result);
    }
    
    // test abnormal scenario
    @Test
    public void testValidateDNameAbnormal()
    {
    	// prepare test data
    	Map<String, String> paramMap = new HashMap<String, String>();
    	
    	// test without setting dntype
    	boolean result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);
    	
    	// test setting illegal dntype: not a number 
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, "abc");
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);
    	
    	// test setting illegal dntype: not 0,1,2,3,4
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, "-1");
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result); 
    	
    	// test setting global type to global but without setting other dnames for global
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_GLOBAL));
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);
    	

    	// test setting global type to server&client but without setting other dnames for server
    	paramMap.clear(); // clear data before test
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP));
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);
    	
    	// test setting global type to server&client but without setting other dnames for client
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP));
    	prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_CLIENT);
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);
    	
    	// test setting global type to server&client but without setting other dnames for CA
    	paramMap.put(CertParamTemplate.PARAMETER_DNAME_TYPE, String.valueOf(CertParamTemplate.PARAMETER_DNAME_TYPE_CLIENTANDSERVERSEP));
    	prepareDnameForMap(paramMap, CertParamTemplate.PARAMETER_PREFIX_SERVER);
    	result = TSOPropsRuleChecker.validateDName(paramMap);
    	
    	assertFalse(result);

    }
    
    private void prepareDnameForMap(Map<String, String> paramMap, String prefix)
    {
    	paramMap.put(prefix + "." + CertParamTemplate.PARAMETER_DNAME_OU, "not null value");
    	paramMap.put(prefix + "." + CertParamTemplate.PARAMETER_DNAME_O, "not null value");
    	paramMap.put(prefix + "." + CertParamTemplate.PARAMETER_DNAME_L, "not null value");
    	paramMap.put(prefix + "." + CertParamTemplate.PARAMETER_DNAME_ST, "not null value");
    	paramMap.put(prefix + "." + CertParamTemplate.PARAMETER_DNAME_C, "not null value");
    }
  
    
}
