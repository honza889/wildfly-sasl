package org.wildfly.sasl.test;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslServer;

import org.jboss.byteman.contrib.bmunit.BMScript;
import org.jboss.byteman.contrib.bmunit.BMUnitRunner;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A test case to test the server side of the Digest mechanism with byteman. (experimental)
 *
 * Examples of byteman tests: https://github.com/hornetq/hornetq/tree/master/tests/byteman-tests
 * 
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(BMUnitRunner.class)
public class DigestBytemanTest extends BaseTestCase {
	
	private static final String DIGEST = "DIGEST-MD5";
    private static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
    private static final String PRE_DIGESTED_PROPERTY = "org.wildfly.sasl.digest.pre_digested";
	
	@BMScript(value="nonrandom-nonce", dir="src/test/byteman-scripts")
	@Test
	public void testSuccessfulExchange() throws Exception {
        CallbackHandler serverCallback = new ServerCallbackHandler("George", "gpwd".toCharArray());
        Map<String, Object> serverProps = new HashMap<String, Object>();
        serverProps.put(REALM_PROPERTY, "TestRealm");
        SaslServer server = Sasl.createSaslServer(DIGEST, "TestProtocol", "TestServer", serverProps, serverCallback);

        CallbackHandler clientCallback = new ClientCallbackHandler("George", "gpwd".toCharArray());
        SaslClient client = Sasl.createSaslClient(new String[]{DIGEST}, "George", "TestProtocol", "TestServer", Collections.<String, Object>emptyMap(), clientCallback);
        assertFalse(client.hasInitialResponse());
        
        byte[] message = server.evaluateResponse(new byte[0]);
        
        //System.out.println(new String(message,"UTF-8")); // debug
        assertTrue(new String(message,"UTF-8").equals("realm=\"TestRealm\",nonce=\"OA6MHXh6VqTrRk\",charset=utf-8,algorithm=md5-sess"));
        
        message = client.evaluateChallenge(message);
        
        //System.out.println(new String(message,"UTF-8")); // debug
        assertTrue(new String(message,"UTF-8").equals("charset=utf-8,username=\"George\",realm=\"TestRealm\",nonce=\"OA6MHXh6VqTrRk\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"TestProtocol/TestServer\",maxbuf=65536,response=e6024a8cc1378dea5a1370ce2cb19bb8,qop=auth,authzid=\"George\""));
        
        server.evaluateResponse(message);
        assertTrue(server.isComplete());
        assertEquals("George", server.getAuthorizationID());
    }
	
}
