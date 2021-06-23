package org.jenkinsci.plugins.gitclient;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.FilePath;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import sun.security.util.Pem;

import java.io.*;
import java.util.Base64;

public class OpenSSHKeyImpl {

    private final static byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes();
    private final static String HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private String keyValue;
    private String passphrase;

    public OpenSSHKeyImpl(final String keyValue, final String passphrase) {
        this.keyValue = keyValue;
        this.passphrase = passphrase;
    }

    public boolean isOpenSSHFormat() {
        return this.keyValue.regionMatches(false, 0, HEADER, 0, HEADER.length());
    }

    /*package*/byte[] decodeOpenSSHKey() {
        byte[] content = Base64.getDecoder().decode(this.keyValue);
        return null;
    }

    /*package*/PemObject getPEMObject() {
        if (!passphrase.isEmpty()) {
            byte[] content = decodeOpenSSHKey();
            return new PemObject("OPENSSH KEY FORMAT", content);
        } else {
            return new PemObject("OPENSSH KEY FORMAT", keyValue.getBytes());
        }
    }
}
