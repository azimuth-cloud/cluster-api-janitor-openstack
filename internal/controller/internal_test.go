/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import "testing"

func TestOtherFinalizer(t *testing.T) {
	cases := []struct {
		name       string
		finalizers []string
		skip       string
		want       string
	}{
		{"multiple, one to skip", []string{"a.finalizer", Finalizer, "b.finalizer"}, Finalizer, "a.finalizer"},
		{"empty list", nil, Finalizer, ""},
		{"single matching (skip target only)", []string{Finalizer}, Finalizer, ""},
		{"single non-matching", []string{"other.finalizer"}, Finalizer, "other.finalizer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := otherFinalizer(c.finalizers, c.skip)
			if got != c.want {
				t.Errorf("otherFinalizer(%v, %q) = %q, want %q", c.finalizers, c.skip, got, c.want)
			}
		})
	}
}
