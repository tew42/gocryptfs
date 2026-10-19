package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Test -init with -plaintextnames -cfsext
func TestInitCfsExt(t *testing.T) {
	dir := test_helpers.InitFS(t, "-plaintextnames", "-cfsext")
	_, c, err := configfile.LoadAndDecrypt(dir+"/"+configfile.ConfDefaultName, testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagCfsExt) {
		t.Error("CfsExt flag should be set but is not")
	}
	if !c.IsFeatureFlagSet(configfile.FlagPlaintextNames) {
		t.Error("PlaintextNames flag should be set but is not")
	}
	out, err := exec.Command(test_helpers.GocryptfsBinary, "-info", dir).CombinedOutput()
	if err != nil {
		t.Fatalf("-info failed: %v, output: %s", err, out)
	}
	if !strings.Contains(string(out), "CfsExt") {
		t.Errorf("-info output does not mention CfsExt:\n%s", out)
	}
}

// -cfsext without -plaintextnames must be rejected
func TestInitCfsExtRequiresPlaintextnames(t *testing.T) {
	dir, err := os.MkdirTemp(test_helpers.TmpDir, t.Name()+".")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-q", "-init", "-extpass", "echo test", "-scryptn=10", "-cfsext", dir)
	err = cmd.Run()
	exitCode := test_helpers.ExtractCmdExitCode(err)
	if exitCode != exitcodes.Usage {
		t.Fatalf("wrong exit code: have=%d, want=%d", exitCode, exitcodes.Usage)
	}
	if _, err := os.Stat(dir + "/" + configfile.ConfDefaultName); err == nil {
		t.Errorf("%s should not have been created", configfile.ConfDefaultName)
	}
}

// Test -init with -reverse -plaintextnames -cfsext
func TestInitCfsExtReverse(t *testing.T) {
	dir := test_helpers.InitFS(t, "-reverse", "-plaintextnames", "-cfsext")
	_, c, err := configfile.LoadAndDecrypt(dir+"/"+configfile.ConfReverseName, testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(configfile.FlagCfsExt) {
		t.Error("CfsExt flag should be set but is not")
	}
}
