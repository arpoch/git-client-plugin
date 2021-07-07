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

public class GitSSHPrivateKeyBinding extends MultiBinding<SSHUserPrivateKey> implements GitCredentialBindings, SSHKeyUtils {
    final static private String PRIVATE_KEY_VALUE = "PRIVATE_KEY";
    final static private String PASSPHRASE_VALUE = "PASSPHRASE";
    private final Map<String, String> credMap = new LinkedHashMap<>();
    private String gitTool = null;

    @DataBoundConstructor
    public GitSSHPrivateKeyBinding(String credentialsId) {
        super(credentialsId);
        //Variables could be added if required
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
            putGitSSHEnvironmentVariable(credentials, unbindTempDir.getDirPath(),taskListener);
            return new MultiEnvironment(credMap, unbindTempDir.getUnbinder());
        } else {
            return new MultiEnvironment(credMap);
        }
    }

    @Override
    public Set<String> variables(@NonNull  Run<?,?> run) {
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
    protected Class<SSHUserPrivateKey> type() {
        return SSHUserPrivateKey.class;
    }

    private void putGitSSHEnvironmentVariable(SSHUserPrivateKey credentials, FilePath workspace, TaskListener listener) throws IOException, InterruptedException {
        if(((CliGitAPIImpl) getGitClientInstance(listener)).isAtLeastVersion(2,3,0,0)){
            if(Functions.isWindows()){
                credMap.put("GIT_SSH_COMMAND","\"" + getSSHExePath(listener) + "\" -i " + "\"" +
                        SSHKeyUtils.getDecodedPrivateKey(credentials,workspace).getRemote() + "\" -o StrictHostKeyChecking=no");
            }
            else {
                credMap.put("GIT_SSH_COMMAND","ssh -i "+ "\"" +
                        SSHKeyUtils.getDecodedPrivateKey(credentials,workspace).getRemote() + "\" -o StrictHostKeyChecking=no $@");
            }
        }else {
            GenerateSSHScript sshScript = new GenerateSSHScript(credentials,getSSHExePath(listener));
            FilePath tempScript = sshScript.write(credentials,workspace);
            credMap.put("GIT_SSH",tempScript.getRemote());
        }
    }

    @Override
    public GitClient getGitClientInstance(TaskListener listener) throws IOException, InterruptedException {
        Git gitInstance = Git.with(listener, new EnvVars()).using(gitTool);
        return gitInstance.getClient();
    }

    @Override
    public String getSSHExePath(TaskListener listener) throws IOException, InterruptedException {
        return (((CliGitAPIImpl) getGitClientInstance(listener)).getSSHExecutable()).getAbsolutePath();
    }

    protected static final class GenerateSSHScript extends AbstractOnDiskBinding<SSHUserPrivateKey> {

        private final String privateKeyVariable;
        private final String passphraseVariable;
        private final String sshExePath;

        protected GenerateSSHScript(SSHUserPrivateKey credentials,String sshExePath) {
            super(SSHKeyUtils.getPrivateKey(credentials)+":"+SSHKeyUtils.getPassphrase(credentials), credentials.getId());
            this.privateKeyVariable = SSHKeyUtils.getPrivateKey(credentials);
            this.passphraseVariable = SSHKeyUtils.getPassphrase(credentials);
            this.sshExePath = sshExePath;
        }

        @Override
        protected FilePath write(SSHUserPrivateKey credentials, FilePath workspace) throws IOException, InterruptedException {
            FilePath tempFile;
            if(Functions.isWindows()){
                tempFile = workspace.createTempFile("gitSSHScript",".bat");
                tempFile.write("@echo off\r\n"
                                + "\""
                                + this.sshExePath
                                + "\""
                                + " -i "
                                + "\""
                                + SSHKeyUtils.getDecodedPrivateKey(credentials,workspace).getRemote()
                                + "\""
                                + " -o StrictHostKeyChecking=no" , null);
            }else {
                tempFile = workspace.createTempFile("gitSSHScript",".sh");
                tempFile.write("ssh -i "
                                + SSHKeyUtils.getDecodedPrivateKey(credentials,workspace).getRemote()
                                +" -o StrictHostKeyChecking=no $@",null);
                tempFile.chmod(0500);
            }
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
