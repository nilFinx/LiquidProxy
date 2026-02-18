package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

var (
	luaCatchAll  = make(map[int]lua.LValue)
	luaHostMatch = make(map[string]lua.LValue)

	L = lua.NewState()
)

func luaInit() {
	pkg := L.GetGlobal("package").(*lua.LTable)

	currentPath := L.GetField(pkg, "path").String()

	newPath := currentPath + ";./lualibs/?.lua;./scripts/?.lua"

	L.SetField(pkg, "path", lua.LString(newPath))

	err := filepath.Walk("scripts", func(path string, info os.FileInfo, err error) error {
		if strings.Contains(strings.TrimPrefix(path, "scripts/"), "/") {
			if *debug {
				log.Printf("Not loading: %s", path)
			}
		} else {
			if !info.IsDir() {
				top := L.GetTop()
				if err := L.DoFile(path); err != nil {
					panic(err)
				}
				c := L.GetTop() - top
				catchall := L.Get(1)
				var hostmatch *lua.LTable
				if c >= 2 {
					hostmatch = L.CheckTable(2)
				}

				log.Printf("%s %s", catchall, hostmatch)
				if catchall != lua.LNil {
					L.Pop(1)
					luaCatchAll[len(luaCatchAll)] = catchall
				}
				if hostmatch != nil {
					L.Pop(1)
					hostmatch.ForEach(func(key lua.LValue, value lua.LValue) {
						s := key.String()
						if luaHostMatch[s] != nil {
							panic(fmt.Errorf("%s already exists from another file but is referenced in %s", s, path))
						}
						luaHostMatch[s] = value
					})
				}

			}
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func luaProc(w http.ResponseWriter, r *http.Request) bool {
	req := L.NewTable()
	L.SetField(req, "path", lua.LString(r.URL.Path))
	L.SetField(req, "host", lua.LString(r.Header.Get("Host")))
	body, err := io.ReadAll(r.Body)
	log.Printf("awawwaawa %s %s", body, err)
	if err == nil {
		L.SetField(req, "body", lua.LString(body))
	}
	headers := L.NewTable()
	for k, v := range r.Header {
		L.SetField(headers, k, lua.LString(v[0]))
	}
	L.SetField(req, "headers", headers)

	res := L.NewTable()
	resHeaders := L.NewTable()
	L.SetField(res, "headers", resHeaders)

	process := L.NewFunction(func(L *lua.LState) int {
		fmt.Println("Go function called")
		client := &http.Client{}
		resp, err := client.Do(r)
		if err != nil {
			panic(err)
		}

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf("%s", err)))
			return 1
		}
		L.SetField(res, "body", lua.LString(body))
		resp.Body.Close()
		return 0
	})

	top := L.GetTop()
	suc := false
	for _, v := range luaCatchAll {
		if err := L.CallByParam(lua.P{
			Fn:      v,
			NRet:    lua.MultRet,
			Protect: true,
		}, req, res, process); err != nil {
			panic(err)
		}
		if L.GetTop()-top >= 1 {
			suc = L.CheckBool(1)
			if suc {
				break
			}
		}
	}

	if !suc && luaHostMatch[r.Host] != nil {
		if err := L.CallByParam(lua.P{
			Fn:      luaHostMatch[r.Host],
			NRet:    lua.MultRet,
			Protect: true,
		}, req, res, process); err != nil {
			panic(err)
		}
		if L.GetTop()-top >= 1 {
			suc = L.CheckBool(-1)
		}
	}

	if suc {
		resHeaders.ForEach(func(k lua.LValue, v lua.LValue) {
			w.Header().Add(k.String(), v.String())
		})
		b := L.GetField(res, "body")
		if b != nil {
			log.Printf("%s", b)
			w.Write([]byte(b.String()))
		}
	}

	return suc
}
