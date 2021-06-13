package org.jenkinsci.plugins.gitclient;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.model.*;
import hudson.plugins.git.GitTool;
import hudson.tasks.BatchFile;
import hudson.tasks.Shell;
import hudson.tools.ToolProperty;
import jenkins.model.Jenkins;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FilenameUtils;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class GitUsernamePasswordBindTest {
    @Parameterized.Parameters(name = "User {0}: Password {1}: GitToolName {2}: GitToolInstance {3}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                {"randomName", "special%%_342@**", "git", null},
                {"here-aquote", "&Ampersand", JGitTool.MAGIC_EXENAME, null},
                {"semi_colon", "colon:inside", JGitApacheTool.MAGIC_EXENAME, null},
                {"b", "He said \"Hello\", then left.", null, createToolInstance("DEFAULT", "git", null)}
        });
    }

    @Rule
    public final TemporaryFolder tempFolder = new TemporaryFolder();

    @Rule
    public JenkinsRule r = new JenkinsRule();

    private final String username;

    private final String password;

    private final String credentialID = DigestUtils.sha256Hex(("Git Usernanme and Password Binding").getBytes(StandardCharsets.UTF_8));

    private GitTool gitToolInstance;

    private String gitToolName = null;

    private File rootDir = null;
    private FilePath rootFilePath = null;
    private File gitRootRepo = null;
    private UsernamePasswordCredentialsImpl credentials = null;
    private GitUsernamePasswordBind gitCredBind = null;

    public GitUsernamePasswordBindTest(String username, String password, String gitToolName, GitTool gitToolInstance) {
        this.username = username;
        this.password = password;
        this.gitToolName = gitToolName;
        this.gitToolInstance = gitToolInstance;
    }

    public static GitTool createToolInstance(String name, String home, List<? extends ToolProperty<?>> properties) {
        return new GitTool(name, home, properties);
    }

    @Before
    public void basicSetup() throws IOException, InterruptedException {
        Jenkins.get();
        //File init
        rootDir = tempFolder.getRoot();
        rootFilePath = new FilePath(rootDir.getAbsoluteFile());
        gitRootRepo = tempFolder.newFolder();
        assertNotNull(gitRootRepo);

        //Credential init
        credentials = new UsernamePasswordCredentialsImpl(CredentialsScope.GLOBAL, credentialID, "GIt Username and Password Binding Test", this.username, this.password);
        CredentialsProvider.lookupStores(r.jenkins).iterator().next().addCredentials(Domain.global(), credentials);

        //GitUsernamePasswordBind instance
        gitCredBind = new GitUsernamePasswordBind(credentials.getId());
        assertEquals("Type mis-match", StandardUsernamePasswordCredentials.class, gitCredBind.type());


        if (gitToolName == null) {
            gitToolName = gitToolInstance.getGitExe();
        } else {
            gitToolInstance = getToolInstance(gitToolName);
        }
        //Git
        Git git = Git.with(TaskListener.NULL, new EnvVars()).in(gitRootRepo).using(getToolInstance(gitToolName).getGitExe());

        //Git Tool
        Jenkins.get().getDescriptorByType(GitTool.DescriptorImpl.class).getDefaultInstallers().clear();
        Jenkins.get().getDescriptorByType(GitTool.DescriptorImpl.class).setInstallations(gitToolInstance);
    }

    public GitTool getToolInstance(String name) {
        GitTool tool = null;
        switch (name) {
            case "git":
                tool = GitTool.getDefaultInstallation();
                break;
            case "jgit":
                tool = JGitTool.getDefaultInstallation();
                break;
            case "jgitapache":
                tool = JGitApacheTool.getDefaultInstallation();
        }
        return tool;
    }

    @Test
    public void test_GenerateGitScript_write() throws IOException, InterruptedException {
        GitUsernamePasswordBind.GenerateGitScript tempGenScript = new GitUsernamePasswordBind.GenerateGitScript(this.username, this.password, credentials.getId());
        assertEquals("Type mis-match", StandardUsernamePasswordCredentials.class, tempGenScript.type());
        FilePath tempScriptFile = tempGenScript.write(credentials, rootFilePath);
        assertNotNull(tempGenScript);
        assertEquals("Read and Execute permissions to be set:" + tempScriptFile.mode(), 320, tempScriptFile.mode());
        if (!isWindows()) {
            assertEquals("File extension not sh", "sh", FilenameUtils.getExtension(tempScriptFile.getName()));
        } else {
            assertEquals("File extension not bat", "bat", FilenameUtils.getExtension(tempScriptFile.getName()));
        }
        assertTrue("Username not found", tempScriptFile.readToString().contains(this.username));
        assertTrue("Password not found", tempScriptFile.readToString().contains(this.password));
    }

    @Test
    public void test_FreeStyleProject() throws Exception {
        FreeStyleProject prj = r.createFreeStyleProject();
        prj.getBuildWrappersList().add(new SecretBuildWrapper(Collections.<MultiBinding<?>>
                singletonList(new GitUsernamePasswordBind(credentialID))));
        if (isWindows()) {
            prj.getBuildersList().add(new BatchFile("@echo off\necho %Git_Username%:%Git_Password% > auth.txt"));
        } else {
            prj.getBuildersList().add(new Shell("set +x\necho $Git_Username:$Git_Password > auth.txt"));
        }
        Map<JobPropertyDescriptor, JobProperty<? super FreeStyleProject>> p = prj.getProperties();
        r.configRoundtrip((Item) prj);
        SecretBuildWrapper wrapper = prj.getBuildWrappersList().get(SecretBuildWrapper.class);
        assertNotNull(wrapper);
        List<? extends MultiBinding<?>> bindings = wrapper.getBindings();
        assertEquals(1, bindings.size());
        MultiBinding<?> binding = bindings.get(0);
        assertTrue("Keys not set", binding.variables().contains("Git_Username"));
        assertTrue("Keys not set", binding.variables().contains("Git_Password"));
        FreeStyleBuild b = r.buildAndAssertSuccess(prj);
        r.assertLogNotContains(this.password, b);
        assertEquals(username + ':' + password, b.getWorkspace().child("auth.txt").readToString().trim());
    }

    /**
     * inline ${@link hudson.Functions#isWindows()} to prevent a transient
     * remote classloader issue
     */
    private static boolean isWindows() {
        return File.pathSeparatorChar == ';';
    }
}
