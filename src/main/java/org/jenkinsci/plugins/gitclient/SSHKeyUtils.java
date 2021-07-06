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

    static FilePath getDecodedPrivateKey(SSHUserPrivateKey credentials, FilePath workspace) throws InterruptedException, IOException {
        FilePath tempKeyFile = workspace.createTempFile("private",".key");
        convertTOPEM(tempKeyFile,getPrivateKey(credentials),getPassphrase(credentials));
        tempKeyFile.chmod(0500);
        return tempKeyFile;
    }

    static FilePath convertTOPEM(FilePath tempFile, String privateKey,String passphrase) throws IOException {
        try {
            if(!OpenSSHKeyImpl.isOpenSSHFormat(privateKey)) {
                //Will write PEM data, if the key is encoded or not
                tempFile.write(PEMEncodable.decode(privateKey, passphrase.toCharArray()).encode(),null);
                return tempFile;
            }
            else if(OpenSSHKeyImpl.isOpenSSHFormat(privateKey)){
                OpenSSHKeyImpl openSSHKey = new OpenSSHKeyImpl(privateKey,passphrase);
                return openSSHKey.writeOpenSSHPEMFormattedKey(tempFile);
            }
        }
        catch (UnrecoverableKeyException | InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }
}
