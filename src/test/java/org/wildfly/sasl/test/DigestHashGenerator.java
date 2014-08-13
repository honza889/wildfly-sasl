package org.wildfly.sasl.test;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;

/**
 * This should generate responses for Digest MD5 communication, but probably is samething bad :(
 */
public class DigestHashGenerator extends BaseTestCase {

	protected static final String DIGEST = "DIGEST-MD5";
	protected static final String REALM_PROPERTY = "com.sun.security.sasl.digest.realm";
	protected static final String PRE_DIGESTED_PROPERTY = "org.wildfly.sasl.digest.pre_digested";

	private byte[] md5(byte[] input) throws NoSuchAlgorithmException {
		MessageDigest m = MessageDigest.getInstance("MD5");
		m.update(input);
		return m.digest();
	}

	private byte[] hex(byte[] input) throws UnsupportedEncodingException {
		StringBuffer digestString = new StringBuffer();
		for (int i = 0; i < input.length; i++) {
			if ((input[i] & 0x000000ff) < 0x10) {
				digestString.append("0" + Integer.toHexString(input[i] & 0x000000ff));
			} else {
				digestString.append(Integer.toHexString(input[i] & 0x000000ff));
			}
		}
		return digestString.toString().getBytes("UTF-8");
	}

	public byte[] ha2(String method, String digestUri) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		return hex(md5((method + ":" + digestUri).getBytes()));
	}

	public byte[] ha1i(String user, String realm, String password) throws NoSuchAlgorithmException {
		return md5((user + ":" + realm + ":" + password).getBytes());
	}

	public byte[] ha1(byte[] ha1i, String nonce, String clientNonce, String authzid) throws NoSuchAlgorithmException, IOException {
		ByteArrayOutputStream A1 = new ByteArrayOutputStream();
		A1.write(ha1i);
		A1.write(':');
		A1.write(nonce.getBytes());
		A1.write(':');
		A1.write(clientNonce.getBytes());
		A1.write(':');
		A1.write(authzid.getBytes());
		return hex(md5(A1.toByteArray()));
	}

	public byte[] response(byte[] ha1, String nonce, String nonceCount, String clientNonce, String qop, byte[] ha2) throws IOException, NoSuchAlgorithmException {
		ByteArrayOutputStream response = new ByteArrayOutputStream();
		response.write(ha1);
		response.write(':');
		response.write(nonce.getBytes());
		if (nonceCount != null) {
			response.write(':');
			response.write(nonceCount.getBytes());
			response.write(':');
			response.write(clientNonce.getBytes());
			response.write(':');
			response.write(qop.getBytes());
		}
		response.write(':');
		response.write(ha2);
		return hex(md5(response.toByteArray()));
	}
	
	@Test
	public void generate() throws Exception {
		// not work??
		byte[] response = response(
				ha1(ha1i("chris", "elwood.innosoft.com", "secret"), "OA9BSXrbuRhWay", "OA9BSuZWMSpW8m", "george"),
				"OA9BSXrbuRhWay", "00000001", "OA9BSuZWMSpW8m", "auth",
				ha2("acap", "elwood.innosoft.com")
		);
		System.out.println(new String(response));
	}

}
