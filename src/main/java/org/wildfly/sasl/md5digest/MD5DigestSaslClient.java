/*
 * JBoss, Home of Professional Open Source
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.sasl.md5digest;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;

import org.wildfly.sasl.util.ByteStringBuilder;
import org.wildfly.sasl.util.Charsets;
import org.wildfly.sasl.util.SaslQuote;
import org.wildfly.sasl.util.SaslState;
import org.wildfly.sasl.util.SaslStateContext;

/**
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 *
 */
public class MD5DigestSaslClient extends AbstractMD5DigestMechanism implements SaslClient {

    
    private static final String DELIMITER = ",";

    private String[] realms;
    private byte[] nonce;
    private String qop;
    private boolean stale = false;
    private int maxbuf = DEFAULT_MAXBUF;
    private String cipher;
    private String cipher_opts;
    
    private final String authorizationId;
    private final boolean hasInitialResponse;

    private Charset charset = Charsets.LATIN_1;

    /**
     * @param mechanismName
     * @param protocol
     * @param serverName
     * @param callbackHandler
     * @param authorizationId
     * @param hasInitialResponse
     */
    public MD5DigestSaslClient(String mechanism, String protocol, String serverName, CallbackHandler callbackHandler,
            String authorizationId, boolean hasInitialResponse) {
        super(mechanism, protocol, serverName, callbackHandler, FORMAT.CLIENT);

        this.hasInitialResponse = hasInitialResponse;
        this.authorizationId = authorizationId;
    }


    private final SaslState STEP_TWO = new SaslState() {

        @Override
        public byte[] evaluateMessage(SaslStateContext context, byte[] message) throws SaslException {
            HashMap<String, byte[]> parsedChallenge = parseResponse(message);
            noteChallengeData(parsedChallenge);
            return createResponse(parsedChallenge);
        }

    };


    private void noteChallengeData(HashMap<String, byte[]> parsedChallenge) {

        byte[] chb = parsedChallenge.get("charset");
        if (chb != null) {
            String chs = new String(chb);
            if ("utf-8".equals(chs)) {
                charset = Charsets.UTF_8;
            }
        }

        LinkedList<String> realmList = new LinkedList<String>();
        for (String keyWord: parsedChallenge.keySet()) {

            if (keyWord.startsWith("realm")) {
                realmList.add(new String(parsedChallenge.get(keyWord), charset));
            }
            else if (keyWord.equals("qop")) {
                qop = new String(parsedChallenge.get(keyWord), charset);
            }
            else if (keyWord.equals("stale")) {
                stale = Boolean.parseBoolean(new String(parsedChallenge.get(keyWord), charset));
            }
            else if (keyWord.equals("maxbuf")) {
                int maxbuf = Integer.parseInt(new String(parsedChallenge.get(keyWord)));
                if (maxbuf > 0) {
                    this.maxbuf = maxbuf;
                }
            }
            else if (keyWord.equals("nonce")) {
                nonce = parsedChallenge.get(keyWord);
            }
            else if (keyWord.equals("cipher")) {
                cipher_opts = new String(parsedChallenge.get(keyWord), Charsets.UTF_8);
            }
        }

        realms = new String[realmList.size()];
        realmList.toArray(realms);

        choose();

    }


    private void choose() {
        cipher = "";
    }

    private byte[] createResponse(HashMap<String, byte[]> parsedChallenge) throws SaslException {

        ByteStringBuilder digestResponse = new ByteStringBuilder();

        // charset
        if (Charsets.UTF_8.equals(charset)) {
            digestResponse.append("charset=\"");
            digestResponse.append("utf-8");
            digestResponse.append("\"").append(DELIMITER);
        }

        
        final NameCallback nameCallback;
        if (authorizationId != null) {
            nameCallback = new NameCallback("User name", authorizationId);
        } else {
            nameCallback = new NameCallback("User name");
        }

        final PasswordCallback passwordCallback = new PasswordCallback("User password", false);

        
        String realm;
        if (realms != null && realms.length > 1) {
            final RealmChoiceCallback realmChoiceCallBack = new RealmChoiceCallback("User realm", realms, 0, false);
            handleCallbacks(realmChoiceCallBack, nameCallback, passwordCallback);
            realm = realms[realmChoiceCallBack.getSelectedIndexes()[0]];
        } else {
            if (realms == null) {
                
            }
            final RealmCallback realmCallback = new RealmCallback("User realm", realms[0]);
            handleCallbacks(realmCallback, nameCallback, passwordCallback);
            realm = realmCallback.getText();
        }
        
        // username
        digestResponse.append("username=\"");
        String userName = nameCallback.getName();
        digestResponse.append(SaslQuote.quote(userName).getBytes(charset));
        digestResponse.append("\"").append(DELIMITER);

        // realm
        digestResponse.append("realm=");
        digestResponse.append(SaslQuote.quote(realm).getBytes(charset));
        digestResponse.append(DELIMITER);

        // nonce
        digestResponse.append("nonce=\"");
        digestResponse.append(nonce);
        digestResponse.append("\"").append(DELIMITER);

        // cnonce
        digestResponse.append("cnonce=\"");
        byte[] cnonce = generateNonce();
        digestResponse.append(cnonce);
        digestResponse.append("\"").append(DELIMITER);

        // nonce-count
        digestResponse.append("nonce-count=");
        int nonceCount = getNonceCount();
        digestResponse.append(convertToHexBytesWithLeftPadding(nonceCount, 8));
        digestResponse.append(DELIMITER);

        // qop
        if (qop != null) {
            digestResponse.append("qop=");
            digestResponse.append(qop);
            digestResponse.append(DELIMITER);
        }

        // digest-uri
        digestResponse.append("digest-uri=\"");
        digestResponse.append(digestURI);
        digestResponse.append("\"").append(DELIMITER);

        // response
        char[] passwd = null;
        byte[] response_value;
        try {
            passwd = passwordCallback.getPassword();
            passwordCallback.clearPassword();
            response_value = digestResponse(userName, realm, passwd, nonce, nonceCount, cnonce, authorizationId, qop, digestURI);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException("Algorithm not supported", e);
        } finally {
            // wipe out the password
            if (passwd != null) {
                Arrays.fill(passwd, (char)0);
            }
        }
        digestResponse.append("response=");
        digestResponse.append(response_value);
        digestResponse.append(DELIMITER);

        // maxbuf
        if (maxbuf != DEFAULT_MAXBUF) {
            digestResponse.append("maxbuf=");
            digestResponse.append(String.valueOf(maxbuf));
            digestResponse.append(DELIMITER);
        }

        // cipher
        if (cipher != null) {
            digestResponse.append("cipher=");
            digestResponse.append(cipher);
            digestResponse.append(DELIMITER);
        }

        // authzid
        if (authorizationId != null) {
            digestResponse.append("authzid=\"");
            digestResponse.append(SaslQuote.quote(authorizationId).getBytes(Charsets.UTF_8));
            digestResponse.append("\"").append(DELIMITER);
        }

        return digestResponse.toArray();
    }

    /**
     * For now it returns always 1
     * @return
     */
    private int getNonceCount() {
        return 1;
    }

    /* (non-Javadoc)
     * @see org.wildfly.sasl.util.AbstractSaslParticipant#init()
     */
    @Override
    public void init() {
        getContext().setNegotiationState(STEP_TWO);
    }

    @Override
    public boolean hasInitialResponse() {
        return hasInitialResponse;
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        return evaluateMessage(challenge);
    }

}
