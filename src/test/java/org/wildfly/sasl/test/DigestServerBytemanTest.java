package org.wildfly.sasl.test;

import static org.junit.Assert.*;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import org.jboss.byteman.contrib.bmunit.BMRule;
import org.jboss.byteman.contrib.bmunit.BMUnitRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A test case to test the server side of the Digest mechanism with Byteman.
 * 
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(BMUnitRunner.class)
public class DigestServerBytemanTest extends BaseTestCase {
	
	protected static final String DIGEST = "DIGEST-MD5";
	protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
	protected static final String PRE_DIGESTED_PROPERTY = "org.wildfly.sasl.digest.pre_digested";
	
	private SaslServer server;
	
	private void requireIncomplete() throws Exception {
		assertFalse(server.isComplete());
		try {
			server.getAuthorizationID();
			throw new Exception("Not throwed IllegalStateException!");
		} catch (IllegalStateException e) {
		}
	}
	
	/**
	 * Test communication by first example in RFC 2831 [page 18]
	 */
	@Test
	@BMRule(name="Static nonce",
			targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
			targetMethod = "generateNonce",
			action="return \"OA6MG9tEQGm2hh\".getBytes();")
	public void testRfc2831example1() throws Exception {
		
		CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
		Map<String, Object> serverProps = new HashMap<String, Object>();
		serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
		server = Sasl.createSaslServer(DIGEST, "imap", "elwood.innosoft.com", serverProps, serverCallback);
		requireIncomplete();
		
		byte[] message1 = server.evaluateResponse(new byte[0]);
		assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
		requireIncomplete();

		byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",response=d388dad90d4bbd760a152321f2143af7,qop=auth".getBytes();
		byte[] message3 = server.evaluateResponse(message2);
		assertEquals("rspauth=ea40f60335c427b5527b84dbabcdfffd", new String(message3, "UTF-8"));
		assertTrue(server.isComplete());
		assertEquals("chris", server.getAuthorizationID());
		
	}
	
	/**
	 * Test communication by second example in RFC 2831 [page 19]
	 */
	@Test
	@BMRule(name="Static nonce",
			targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
			targetMethod = "generateNonce",
			action="return \"OA9BSXrbuRhWay\".getBytes();")
	public void testRfc2831example2() throws Exception {
		
		CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
		Map<String, Object> serverProps = new HashMap<String, Object>();
		serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
		server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
		requireIncomplete();
		
		byte[] message1 = server.evaluateResponse(new byte[0]);
		assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
		requireIncomplete();

		byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=6084c6db3fede7352c551284490fd0fc,qop=auth".getBytes();
		byte[] message3 = server.evaluateResponse(message2);
		assertEquals("rspauth=2f0b3d7c3c2e486600ef710726aa2eae", new String(message3, "UTF-8"));
		assertTrue(server.isComplete());
		assertEquals("chris", server.getAuthorizationID());
		
	}
	
	/**
	 * Test with authorization ID (authzid) of else user
	 */
	@Test
	@BMRule(name="Static nonce",
			targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
			targetMethod = "generateNonce",
			action="return \"OA9BSXrbuRhWay\".getBytes();")
	public void testUnauthorizedAuthorizationId() throws Exception {
		
		CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
		Map<String, Object> serverProps = new HashMap<String, Object>();
		serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
		server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
		requireIncomplete();
		
		byte[] message1 = server.evaluateResponse(new byte[0]);
		assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
		requireIncomplete();
		
		byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=0d071450228e395e2c0999e02b6aa665,qop=auth,authzid=\"george\"".getBytes();
		
		try{
			server.evaluateResponse(message2);
			throw new Exception("Not throwed SaslException!");
		} catch (SaslException e) {
			assertEquals("DIGEST-MD5: chris is not authorized to act as george", e.getMessage());
		}
		assertFalse(server.isComplete());
		
	}
	
	/**
	 * Test with authorization ID (authzid) - authorized
	 */
	@Test
	@BMRule(name="Static nonce",
			targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
			targetMethod = "generateNonce",
			action="return \"OA9BSXrbuRhWay\".getBytes();")
	public void testAuthorizedAuthorizationId() throws Exception {
		
		CallbackHandler serverCallback = new ServerCallbackHandler("chris", "secret".toCharArray());
		Map<String, Object> serverProps = new HashMap<String, Object>();
		serverProps.put(REALM_PROPERTY, "elwood.innosoft.com");
		server = Sasl.createSaslServer(DIGEST, "acap", "elwood.innosoft.com", serverProps, serverCallback);
		requireIncomplete();
		
		byte[] message1 = server.evaluateResponse(new byte[0]);
		assertEquals("realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",charset=utf-8,algorithm=md5-sess", new String(message1, "UTF-8"));
		requireIncomplete();
		
		byte[] message2 = "charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",response=aa4e81f1c6656350f7bce05d436665de,qop=auth,authzid=\"chris\"".getBytes();
		byte[] message3 = server.evaluateResponse(message2);
		
		assertEquals("rspauth=af3ca83a805d4cfa00675a17315475c4", new String(message3, "UTF-8"));
		assertTrue(server.isComplete());
		assertEquals("chris", server.getAuthorizationID());
		
	}
	
	// TODO: MD5 / MD5-sess ?
	// TODO: qop = auth / auth-int / auth-conf
	// TODO: authzid
}