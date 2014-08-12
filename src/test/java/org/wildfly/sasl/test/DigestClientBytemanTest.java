package org.wildfly.sasl.test;

import static org.junit.Assert.*;

import java.util.Collections;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

import org.jboss.byteman.contrib.bmunit.BMRule;
import org.jboss.byteman.contrib.bmunit.BMUnitRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * A test case to test the client side of the Digest mechanism with Byteman.
 * 
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 */
@RunWith(BMUnitRunner.class)
public class DigestClientBytemanTest extends BaseTestCase {

	protected static final String DIGEST = "DIGEST-MD5";
	protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
	protected static final String PRE_DIGESTED_PROPERTY = "org.wildfly.sasl.digest.pre_digested";

	private SaslClient client;

	/**
	 * Test communication by first example in RFC 2831 [page 18]
	 */
	@Test
	@BMRule(name = "Static nonce",
	        targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
	        targetMethod = "generateNonce",
	        action = "return \"OA6MHXh6VqTrRk\".getBytes();")
	public void testRfc2831example1() throws Exception {

		CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
		client = Sasl.createSaslClient(new String[] { DIGEST }, null, "imap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
		assertFalse(client.isComplete());

		byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
		byte[] message2 = client.evaluateChallenge(message1);
		assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",nc=00000001,cnonce=\"OA6MHXh6VqTrRk\",digest-uri=\"imap/elwood.innosoft.com\",maxbuf=65536,response=d388dad90d4bbd760a152321f2143af7,qop=auth", new String(message2, "UTF-8"));
		assertFalse(client.isComplete());

		byte[] message3 = "rspauth=ea40f60335c427b5527b84dbabcdfffd".getBytes();
		byte[] message4 = client.evaluateChallenge(message3);
		assertEquals(null, message4);
		assertTrue(client.isComplete());

	}

	/**
	 * Test communication by second example in RFC 2831 [page 18]
	 */
	@Test
	@BMRule(name = "Static nonce",
	        targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
	        targetMethod = "generateNonce",
	        action = "return \"OA9BSuZWMSpW8m\".getBytes();")
	public void testRfc2831example2() throws Exception {

		CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
		client = Sasl.createSaslClient(new String[] { DIGEST }, null, "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
		assertFalse(client.hasInitialResponse());
		assertFalse(client.isComplete());

		byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
		byte[] message2 = client.evaluateChallenge(message1);
		assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=6084c6db3fede7352c551284490fd0fc,qop=auth", new String(message2, "UTF-8"));
		assertFalse(client.isComplete());

		byte[] message3 = "rspauth=2f0b3d7c3c2e486600ef710726aa2eae".getBytes();
		byte[] message4 = client.evaluateChallenge(message3);
		assertEquals(null, message4);
		assertTrue(client.isComplete());

	}
	
	/**
	 * Test with authorization ID (authzid) - authorized
	 */
	@Test
	@BMRule(name = "Static nonce",
	        targetClass = "com.sun.security.sasl.digest.DigestMD5Base",
	        targetMethod = "generateNonce",
	        action = "return \"OA9BSuZWMSpW8m\".getBytes();")
	public void testAuthorizedAuthorizationId() throws Exception {

		CallbackHandler clientCallback = new ClientCallbackHandler("chris", "secret".toCharArray());
		client = Sasl.createSaslClient(new String[] { DIGEST }, "chris", "acap", "elwood.innosoft.com", Collections.<String, Object> emptyMap(), clientCallback);
		assertFalse(client.hasInitialResponse());
		assertFalse(client.isComplete());

		byte[] message1 = "realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",qop=\"auth\",algorithm=md5-sess,charset=utf-8".getBytes();
		byte[] message2 = client.evaluateChallenge(message1);
		assertEquals("charset=utf-8,username=\"chris\",realm=\"elwood.innosoft.com\",nonce=\"OA9BSXrbuRhWay\",nc=00000001,cnonce=\"OA9BSuZWMSpW8m\",digest-uri=\"acap/elwood.innosoft.com\",maxbuf=65536,response=aa4e81f1c6656350f7bce05d436665de,qop=auth,authzid=\"chris\"", new String(message2, "UTF-8"));
		assertFalse(client.isComplete());

		byte[] message3 = "rspauth=af3ca83a805d4cfa00675a17315475c4".getBytes();
		byte[] message4 = client.evaluateChallenge(message3);
		assertEquals(null, message4);
		assertTrue(client.isComplete());

	}
	
}
