package hysteria2

import (
	"sync"
	"testing"
)

func TestAuthoritativeUsersKeepExactSessionIdentity(t *testing.T) {
	service := &Service[string]{}
	done := make(chan struct{})
	close(done)
	removed := &serverSession[string]{Service: service, connDone: done}
	kept := &serverSession[string]{Service: service, connDone: done}
	service.sessions = map[*serverSession[string]]string{removed: "removed", kept: "kept"}
	service.UpdateUsers([]string{"kept"}, []string{"password"})
	if len(service.sessions) != 1 || service.sessions[kept] != "kept" {
		t.Fatal("wrong user session retained")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				service.UpdateUsers([]string{"kept"}, []string{"password"})
				service.authMu.RLock()
				_ = len(service.userMap)
				service.authMu.RUnlock()
			}
		}()
	}
	wg.Wait()
	if len(service.sessions) != 1 {
		t.Fatal("valid session removed by refresh")
	}
}
