package org.g4.certificate.parser.gen;

import org.g4.certificate.parser.CertGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.FileUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class CertGenParamParserTest {
	private CertGenParamParser ph = null;
	private Parameters parameters = null;
	private String[] paramArray = null;
	@Before
    public void setUp() throws Exception {
		ph = new CertGenParamParser(); // tested class
		parameters = new Parameters(); // test data
		paramArray = new String[0];
    }

    @After
    public void tearDown() throws Exception {

    }
    
    // test -tso parameter and with different upper case and lower case
    @Test
    public void testanalyzeParams4TSONormal()
    {
    	// test "-tso"
    	boolean result =ph.analyzeParams(parameters.addParameter("-tso").getParameters(), paramArray);
    	assertTrue(result && ph.isTSO());
    	
    	// test "-tSO"
    	result =ph.analyzeParams(parameters.addParameter("-tSO", true).getParameters(), paramArray);
    	assertTrue(result && ph.isTSO());
    }
    
    // test -f5 parameter and with different upper case and lower case
    @Test
    public void testanalyzeParams4F5Normal()
    {
    	// test "-f5"
    	boolean result = ph.analyzeParams(parameters.addParameter("-f5").getParameters(), paramArray);
    	assertTrue(ph.isF5() && result);
    	// test "-F5"
    	result = ph.analyzeParams(parameters.addParameter("-F5", true).getParameters(), paramArray);
    	assertTrue(ph.isF5() && result);
    }
    
    // test -apache parameter and with different upper case and lower case
    @Test
    public void testanalyzeParams4ApacheNormal()
    {
    	// test "-apache"
    	boolean result = ph.analyzeParams(parameters.addParameter("-apache").getParameters(), paramArray);
    	assertTrue(ph.isApache() && result);
    	
    	// test "-apAche"
    	result = ph.analyzeParams(parameters.addParameter("-apAche", true).getParameters(), paramArray);
    	assertTrue(ph.isApache() && result);	
    }
    
    // test with multiple type, like -tso or apache
    @Test
    public void testanalyzeParamsWithMultipleType()
    {
    	// test specified both "-tso -f5"
    	boolean result =ph.analyzeParams(parameters.addParameter("-tso").addParameter("-f5").getParameters(), paramArray);
    	assertFalse(result);
    	
    	// test specified both "-tso -TSO -apache"
    	result =ph.analyzeParams(parameters.addParameter("-tso", true).addParameter("-TSO").addParameter("-apache").getParameters(), paramArray);
    	assertFalse(result);
    }
    
    // test without specified any type like tso/f5/apache
    @Test
    public void testanalyzeParamsWithoutType()
    {
    	// test "-kt"
    	boolean result = ph.analyzeParams(parameters.addParameter("-kt").getParameters(), paramArray);
    	assertFalse(result);
    }

    // ensure  -kt, -t, -help, -h are legal parameter
    @Test
    public void testanalyzeParams4LegalParameter()
    {
    	// test "-tso -kt -help -h"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-kt").addParameter("-help").addParameter("-h").getParameters(), paramArray);
    	assertTrue(result && ph.isHelp() && ph.isKeepTemp());
    	
    }
    
 // test when -h, -help, -t, -kt is not specified, deault value is false
    @Test
    public void testanalyzeParams4DefaultValue()
    {	
    	// test "-tso"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso", true).getParameters(), paramArray);
    	assertTrue(result && !ph.isHelp() && !ph.isKeepTemp()); 	
    }
    
    // ensure  -config work fine
    @Test
    public void testanalyzeParams4ConfNomal()
    {
    	// prepare test file
    	 FileUtil.createFile(new ByteArrayInputStream("test string".getBytes()), FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE);
    	// test "-tso -config  FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE "
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-config").addParameter(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE).getParameters(), paramArray);
    	// assert test result
    	assertTrue(result && ph.getConfFile() != null && ph.getConfFile().equals(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE));
    	
    	// delete test file
    	FileUtil.deleteFile(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE);
    	
    	
    }
    
    // test conf without file
    @Test
    public void testanalyzeParams4ConfWithoutSpecifiedFile()
    {
    	// test "-tso -config"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-config").getParameters(), paramArray);
    	
    	assertFalse(result);
    }
    
    // test conf without file
    @Test
    public void testanalyzeParams4ConfWithoutLegalFile()
    {
    	// test "-tso -config abc"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-config").addParameter("abc").getParameters(), paramArray);
    	
    	assertFalse(result);
    }
    
     // test multiple -config
    @Test
    public void testanalyzeParams4ConfWithMutipleConfig()
    {
    	// prepare test file
    	FileUtil.createFile(new ByteArrayInputStream("test string".getBytes()), FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE);
   	 
    	// test "-tso -config abc -config  FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-config").addParameter("abc")
    																	 .addParameter("-config").addParameter(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE)
    																	 .getParameters(), paramArray);
    	
    	assertFalse(result);
    	
    	// test "-tso -config  FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE  -config FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE  "
    	result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-config").addParameter(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE)
    																	 .addParameter("-config").addParameter(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE )
    																	 .getParameters(), paramArray);
    	
    	assertFalse(result);
    	
    	// delete test file
    	FileUtil.deleteFile(FileUtil.getJarCurrentPath() + CertParamTemplate.SM_TSO_CERT_PROPS_FILE);
    }
    
    // ensure  -jre_home work fine
    @Test
    public void testanalyzeParams4JreNomal()
    {
    	// prepare test java home
    	String javaHome = FileUtil.getJarCurrentPath() +"jre";
    	System.out.println(" javahome : " + javaHome);
    	FileUtil.createDir(javaHome);
    	javaHome +=File.separator + "lib";
    	FileUtil.createDir(javaHome);
    	javaHome +=File.separator + "security";
    	FileUtil.createDir(javaHome);
    	FileUtil.createFile(new ByteArrayInputStream("test string".getBytes()), javaHome + File.separator + "cacerts");
      	 
    	// test "-tso -jre_home  FileUtil.getJarCurrentPath()"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-jre_home").addParameter(FileUtil.getJarCurrentPath()).getParameters(), paramArray);
    	
    	assertTrue(result); // TODO: did not validate its a true jre home
    	assertNotNull(ph.getJREHome());
    	
    	// detele test java home
    	FileUtil.deleteDir(FileUtil.getJarCurrentPath() +File.separator + "jre");
    	
    	
    }
    
    // test jre_home without file
    @Test
    public void testanalyzeParams4JREWithoutSpecifiedFile()
    {
    	// test "-tso -jre_home"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-jre_home").getParameters(), paramArray);
    	
    	assertFalse(result);
    	
    	// test "-tso -jre_home -ddd"
    	result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-jre_home").addParameter("-ddd").getParameters(), paramArray);
    	
    	assertFalse(result);
    }
    
    // test jre_home without illegal java home direcotry
    @Test
    public void testanalyzeParams4JREWithIllegalJavaHomeDir()
    {
    	
    	// test "-tso -jre_home FileUtil.getJarCurrentPath()"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-jre_home").addParameter(FileUtil.getJarCurrentPath()).getParameters(), paramArray);
    	
    	assertFalse(result);
    }
    
    // test duplicate parameters which is illegal, e.g.  -t -t is illegal
    @Test
    public void testDuplicateParameters()
    {
    	
    	// test "-tso -jre_home -jre_home"
    	boolean result = ph.analyzeParams(parameters.addParameter("-tso").addParameter("-jre_home").addParameter("-jre_home").getParameters(), paramArray);
    	
    	assertFalse(result);
    }
    
    // test isInvalidParameter work normal
    @Test
    public void testIsInvalidParameterNomal()
    {
    	
    	String[] testArr = new String[]{"-11", "-22","-44"};
    	String[] scopeArr = new String[]{"-11", "-22",  "-33"};
    	boolean result = ph.isInvalidParameter(testArr, scopeArr);
    	
    	assertTrue(result); 
    }
    
    // test isInvalidParameter work normal
    @Test
    public void testIntialAnalysisNomal()
    {
    	
    	// test // test "-tso -apache -f5 -help -h"
    	ph.analyzeParams(parameters.addParameter("-tso").addParameter("-f5").addParameter("-apache").addParameter("-help").addParameter("-h").getParameters(), paramArray);
    	
    	assertTrue(ph.isApache()); 
    	assertTrue(ph.isF5());
    	assertTrue(ph.isHelp());
    	assertTrue(ph.isTSO());
    }
    

    
    // Simulate parameters customer input
    private  class Parameters
    {
    	private  List<String> paramList = new ArrayList<String>();

    	// do not clean parameter list;
    	public  Parameters addParameter(String param)
    	{
    		 return addParameter(param, false);
    	}
    	
    	public  Parameters addParameter(String param, boolean isClean)
    	{
    		if(isClean) paramList.clear(); // clear parameter array
    		paramList.add(param);
    		return this;
    	}
    	
    	public String[] getParameters()
    	{
    		return getArray(paramList);
    	}
    	
    	private String[] getArray(List<String> list)
        {
        	String[] result = new String[list.size()];
        	list.toArray(result);
        	return result;
        }
    }
    
    
}
