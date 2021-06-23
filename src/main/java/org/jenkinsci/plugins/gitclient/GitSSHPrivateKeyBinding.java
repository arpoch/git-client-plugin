package org.jenkinsci.plugins.gitclient;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.*;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.AbstractOnDiskBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.UnbindableDir;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nullable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.*;

public class GitSSHPrivateKeyBinding extends MultiBinding<SSHUserPrivateKey> implements GitCredentialBindings {
    final static private String PRIVATE_KEY_VALUE = "PRIVATE_KEY";
    final static private String PASSPHRASE_VALUE = "PASSPHRASE";
    static private PemObject PEM;
    private final Map<String, String> credMap = new LinkedHashMap<>();
    private String gitTool = null;

    @DataBoundConstructor
    public GitSSHPrivateKeyBinding(String credentialsId) {
        super(credentialsId);
        //Variables could be added if required
    }

    @Override
    protected Class<SSHUserPrivateKey> type() {
        return SSHUserPrivateKey.class;
    }

    @Override
    public MultiEnvironment bind(@NonNull Run<?, ?> run, @Nullable FilePath filePath,
                                 @Nullable Launcher launcher, @NonNull TaskListener taskListener) throws IOException, InterruptedException {
        SSHUserPrivateKey credentials = getCredentials(run);
        setKeyBindings(credentials);
        gitTool = gitToolName(run, taskListener);
        if (gitTool != null && filePath != null) {
            final UnbindableDir unbindTempDir = UnbindableDir.create(filePath);
            setRunEnvironmentVariables(filePath, taskListener);
            OpenSSHKeyImpl opensSSH = new OpenSSHKeyImpl(getPrivateKey(credentials),getPassphrase(credentials));
            PEM = opensSSH.getPEMObject();
            GenerateSSHScript sshEcho = new GenerateSSHScript(getPrivateKey(credentials),getPassphrase(credentials),
                                                getCredentialsId(),PEM);
            FilePath sshTempFile = sshEcho.write(credentials,unbindTempDir.getDirPath());
            //credMap.put("",);
            return new MultiEnvironment(credMap, unbindTempDir.getUnbinder());
        } else {
            return new MultiEnvironment(credMap);
        }
    }

    @Override
    public Set<String> variables() {
        Set<String> keys = new LinkedHashSet<>();
        keys.add(PRIVATE_KEY_VALUE);
        keys.add(PASSPHRASE_VALUE);
        return keys;
    }

    @Override
    public void setKeyBindings(@NonNull StandardCredentials credentials) {
        //Only one key is allowed
        credMap.put(PRIVATE_KEY_VALUE, ((SSHUserPrivateKey) credentials).getPrivateKeys().get(0));
        //TODO does passphrase should need to be string or secret
        credMap.put(PASSPHRASE_VALUE, Secret.toString(((SSHUserPrivateKey) credentials).getPassphrase()));
    }

    @Override
    public void setRunEnvironmentVariables(@NonNull FilePath filePath, @NonNull TaskListener listener) throws IOException, InterruptedException {
        if (!Functions.isWindows() && ((CliGitAPIImpl) getGitClientInstance(listener)).
                isAtLeastVersion(2, 3, 0, 0)) {
            credMap.put("GIT_TERMINAL_PROMPT", "false");
        } else {
            credMap.put("GCM_INTERACTIVE", "false");
        }
    }

    @Override
    public GitClient getGitClientInstance(TaskListener listener) throws IOException, InterruptedException {
        Git gitInstance = Git.with(listener, new EnvVars()).using(gitTool);
        return gitInstance.getClient();
    }

    static private String getPrivateKey(SSHUserPrivateKey credentials) {
        return credentials.getPrivateKeys().get(0);
    }

    static private String getPassphrase(SSHUserPrivateKey credentials) {
      return Secret.toString(credentials.getPassphrase());
    }

    protected static final class GenerateSSHScript extends AbstractOnDiskBinding<SSHUserPrivateKey> {

        private final String privateKeyVariable;
        private final String passphraseVariable;
        private final PemObject pemObj;

        protected GenerateSSHScript(String privateKeyVariable, String passphraseVariable, String credentialsId,PemObject pem) {
            super(privateKeyVariable+":"+passphraseVariable, credentialsId);
            this.privateKeyVariable = privateKeyVariable;
            this.passphraseVariable = passphraseVariable;
            this.pemObj = pem;
        }

        @Override
        protected FilePath write(SSHUserPrivateKey credentials, FilePath workspace) throws IOException, InterruptedException {
            FilePath tempFile  = workspace.createTempFile("private",".key");
            PemWriter tempPEMWrite = new PemWriter(new OutputStreamWriter(new FileOutputStream
                    (new File(tempFile.toURI()))));
            tempPEMWrite.writeObject(pemObj);
            tempPEMWrite.close();
            tempFile.chmod(0500);
            return tempFile;
        }

        @Override
        protected Class<SSHUserPrivateKey> type() {
            return SSHUserPrivateKey.class;
        }
    }

    @Symbol("GitSSHPrivateKey")
    @Extension
    public static final class DescriptorImpl extends BindingDescriptor<SSHUserPrivateKey> {

        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.GitSSHPrivateKeyBind_DisplayName();
        }

        @Override
        protected Class<SSHUserPrivateKey> type() {
            return SSHUserPrivateKey.class;
        }

        @Override
        public boolean requiresWorkspace() {
            return true;
        }
    }
}
