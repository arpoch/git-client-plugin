package org.jenkinsci.plugins.gitclient;

import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyV1KeyFile;
import hudson.FilePath;
import net.schmizz.sshj.userauth.password.PasswordFinder;
import net.schmizz.sshj.userauth.password.Resource;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

public class OpenSSHKeyImpl {

    //TODO Remove if no use found
    private final static byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);
    private final static String HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private String keyValue;
    private String passphrase;

    public OpenSSHKeyImpl(final String keyValue, final String passphrase) {
        this.keyValue = keyValue;
        this.passphrase = passphrase;
    }

    public static boolean isOpenSSHFormat(String keyValue) {
        return keyValue.regionMatches(false, 0, HEADER, 0, HEADER.length());
    }

    PrivateKey getOpenSSHKeyPair() throws IOException {
        OpenSSHKeyV1KeyFile o = new OpenSSHKeyV1KeyFile();
        o.init(this.keyValue,"", new PassphraseFinder(this.passphrase));
        return o.getPrivate();
    }

    private PemObject getPEMObject() throws IOException {
        byte[] content;
        if (passphrase.isEmpty()) {
            content = this.keyValue.getBytes(StandardCharsets.UTF_8);
        } else {
            PrivateKey privateKey = getOpenSSHKeyPair();
            content = privateKey.getEncoded();
        }
        return new PemObject("PRIVATE KEY", content);
    }

    private PemWriter getPEMWriter(FilePath tempFile) throws IOException, InterruptedException {
        return new PemWriter(new OutputStreamWriter( new FileOutputStream(new File(tempFile.toURI())),StandardCharsets.UTF_8));
    }

    FilePath writeOpenSSHPEMFormattedKey(FilePath tempFile) throws IOException, InterruptedException {
        PemObject pemObj = this.getPEMObject();
        PemWriter pemWriter = this.getPEMWriter(tempFile);
        pemWriter.writeObject(pemObj);
        pemWriter.close();
        return tempFile;
    }

    protected static final class PassphraseFinder implements PasswordFinder {

        private final String passphrase;

        public PassphraseFinder(String passphrase){
            this.passphrase=passphrase;
        }

        @Override
        public char[] reqPassword(Resource<?> resource) {
            return this.passphrase.toCharArray();
        }

        @Override
        public boolean shouldRetry(Resource<?> resource) {
            return false;
        }
    }
}
