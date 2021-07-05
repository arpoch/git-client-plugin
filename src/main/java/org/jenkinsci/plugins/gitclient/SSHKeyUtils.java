package org.jenkinsci.plugins.gitclient;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import hudson.FilePath;
import hudson.model.TaskListener;
import hudson.util.Secret;
import jenkins.bouncycastle.api.PEMEncodable;

import java.io.IOException;
import java.security.UnrecoverableKeyException;

public interface SSHKeyUtils {

    String getSSHExePath(TaskListener listener) throws IOException, InterruptedException;

    static String getPrivateKey(SSHUserPrivateKey credentials) {
        return credentials.getPrivateKeys().get(0);
    }

    static String getPassphrase(SSHUserPrivateKey credentials) {
        return Secret.toString(credentials.getPassphrase());
    }

    static FilePath getDecodedPrivateKey(SSHUserPrivateKey credentials, FilePath workspace) throws IOException, InterruptedException, IOException {
        FilePath tempKeyFile = workspace.createTempFile("private",".key");
        tempKeyFile.write(convertTOPEM(getPrivateKey(credentials),getPassphrase(credentials)),null);
        tempKeyFile.chmod(0500);
        return tempKeyFile;
    }

    static String convertTOPEM(String privateKey,String passphrase) throws IOException {
        try {
            if(OpenSSHKeyImpl.isOpenSSHFormat(privateKey)){
                OpenSSHKeyImpl opensSSH = new OpenSSHKeyImpl(privateKey,passphrase);
                return null;
            }
            else{
                return PEMEncodable.decode(privateKey,passphrase.toCharArray()).encode();
            }
        }
        catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            return null;
        }
    }
}
