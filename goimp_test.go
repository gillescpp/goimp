package goimp

import "testing"

func TestImpersontation(t *testing.T) {
	// test current username
	u, err := UserName()
	if err != nil {
		t.Errorf("%v", err)
	}
	t.Log("current username", u)

	//impersonation to user "test"
	err = Impersonate("test", "testtest")
	if err != nil {
		t.Errorf("%v", err)
	}
	//defer Revert()

	// test new username
	u, _ = UserName()
	t.Log("new username", u)

	//revert
	err = Revert()
	if err != nil {
		t.Errorf("%v", err)
	}

	// test final username
	u, _ = UserName()
	t.Log("after revert username", u)
}
