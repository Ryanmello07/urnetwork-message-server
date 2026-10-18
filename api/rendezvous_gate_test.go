package api

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/message-server/store"
)

// ── the gates over this package's source, resolved by type ───────────────────────────────────
//
// WHAT THE TWO GATES BELOW HOLD, AND WHY THEY TYPE-CHECK (LRI R75, T1 and T2). §5.1.2: "no
// transaction is opened and no row is allocated before check 7 has passed". The first gate holds
// every link box write to the arm that owns it; the second holds each arm's verifier to a top-level
// statement of the arm's body, ahead of every write the arm makes.
//
// They read this package as the compiler does: go/types over its source, every import read from the
// export data the go command builds for it. A call is then a write because of what its receiver's
// type and its method are, and not because of how the receiver is spelled: a write through a local
// alias of the store, through a parameter, through a method value, or inside a helper of this
// package the arm calls, is a write where the arm makes it. The gates they replace matched a holder
// by its field name and ordered writes by source position at any depth, and the review's two
// mutants walked through both: ALIAS-COLLECT deleted through the ack via `boxes := self.linkBoxes`
// before check 7, and BRANCH-COLLECT wrapped Collect's verifier in `if !request.GetSubscribe()`.

// The [store.LinkBoxes] methods that change a row, and the ones that do not. Written down with its
// reason, as storeMethodMutates is; what is derived is its completeness.
var linkBoxMethodMutates = map[string]bool{
	"RegisterLinkBox": true,  // §4.3.11's Register
	"DepositLinkBox":  true,  // Deposit
	"CollectLinkBox":  true,  // Collect deletes through its acknowledgement
	"RetireLinkBox":   true,  // Retire
	"LinkBox":         false, // Q17
	"LiveLinkBoxes":   false, // Q20
}

// The arm each write belongs to.
var linkBoxWriteArm = map[string]string{
	"RegisterLinkBox": "RendezvousRegister",
	"DepositLinkBox":  "RendezvousDeposit",
	"CollectLinkBox":  "RendezvousCollect",
	"RetireLinkBox":   "RendezvousRetire",
}

// The [Subscriptions] methods that change nothing. Every other method of it is a change to the
// registry, so that a method added to it is a change until it is written down here as a read.
var subscriptionReads = map[string]bool{
	"RendezvousSubscriptions": true,
	"Stats":                   true,
}

// This package, type-checked once for every gate that reads it.
type checkedPackage struct {
	files  *token.FileSet
	syntax []*ast.File
	info   *types.Info
	types  *types.Package
	// every function and method declared here, by its object
	decls map[*types.Func]*ast.FuncDecl
}

var (
	checkedOnce  sync.Once
	checked      *checkedPackage
	checkedError error
)

func typeCheckThisPackage(t *testing.T) *checkedPackage {
	t.Helper()
	checkedOnce.Do(func() { checked, checkedError = typeCheck() })
	if checkedError != nil {
		t.Fatalf("type-checking this package: %v", checkedError)
	}
	return checked
}

// The go command, found rather than assumed, as the module root's gates find it: on PATH, or beside
// the toolchain that built this test.
func goCommandPath() string {
	if found, err := exec.LookPath("go"); err == nil {
		return found
	}
	return filepath.Join(build.Default.GOROOT, "bin", "go")
}

func typeCheck() (*checkedPackage, error) {
	// the export data of everything this package imports, as the go command builds it
	command := exec.Command(goCommandPath(), "list", "-export", "-deps", "-f", "{{if .Export}}{{.ImportPath}}\t{{.Export}}{{end}}", ".")
	stderr := &strings.Builder{}
	command.Stderr = stderr
	listed, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list -export: %v\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	for _, line := range strings.Split(string(listed), "\n") {
		if path, file, found := strings.Cut(strings.TrimSpace(line), "\t"); found {
			exports[path] = file
		}
	}
	// this package's own files, as the go command would build them here
	described, err := build.Default.ImportDir(".", 0)
	if err != nil {
		return nil, fmt.Errorf("go/build: %v", err)
	}
	files := token.NewFileSet()
	syntax := []*ast.File{}
	for _, name := range described.GoFiles {
		parsed, err := parser.ParseFile(files, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, parsed)
	}
	lookup := func(path string) (io.ReadCloser, error) {
		file, found := exports[path]
		if !found {
			return nil, fmt.Errorf("the go command built no export data for %s", path)
		}
		return os.Open(file)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	config := types.Config{Importer: importer.ForCompiler(files, "gc", lookup)}
	checkedTypes, err := config.Check(described.ImportPath, files, syntax, info)
	if err != nil {
		return nil, err
	}
	decls := map[*types.Func]*ast.FuncDecl{}
	for _, file := range syntax {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok {
				if object, ok := info.Defs[function.Name].(*types.Func); ok {
					decls[object] = function
				}
			}
		}
	}
	return &checkedPackage{files: files, syntax: syntax, info: info, types: checkedTypes, decls: decls}, nil
}

// The package this one imports at `path`, as the type checker resolved it.
func (self *checkedPackage) imported(t *testing.T, path string) *types.Package {
	t.Helper()
	for _, imported := range self.types.Imports() {
		if imported.Path() == path {
			return imported
		}
	}
	t.Fatalf("this package does not import %s", path)
	return nil
}

// The method of *Handler by that name.
func (self *checkedPackage) handlerMethod(t *testing.T, name string) (*types.Func, *ast.FuncDecl) {
	t.Helper()
	handler := self.types.Scope().Lookup("Handler")
	if handler == nil {
		t.Fatal("this package declares no Handler")
	}
	object, _, _ := types.LookupFieldOrMethod(types.NewPointer(handler.Type()), true, self.types, name)
	method, ok := object.(*types.Func)
	if !ok || self.decls[method] == nil {
		t.Fatalf("*Handler has no method %s declared in this package", name)
	}
	return method, self.decls[method]
}

func (self *checkedPackage) at(position token.Pos) string {
	where := self.files.Position(position)
	return fmt.Sprintf("%s:%d", filepath.Base(where.Filename), where.Line)
}

// ── what a function does to state ────────────────────────────────────────────────────────────

// One thing a function does that the gates are about, placed where the function does it.
type effect struct {
	// "write" and "read", a [store.LinkBoxes] method; "registry", a change to [Subscriptions];
	// "opaque", a store.LinkBoxes value handed to code these gates cannot read
	kind string
	name string
	at   token.Pos
	// how it was reached: the receiver as written and its type, or the call that leads to it
	via string
}

func (self effect) String() string {
	return self.kind + " " + self.name + " via " + self.via
}

// THE SUBSCRIPTION REGISTRY'S TWO FILES (LRI R78, N4). Its methods are declared in these and nowhere
// else, which newEffectReader holds in both directions, and a selection of one of its fields made in
// any other file is a change to it made around its methods: FIELD-REGISTRY-2 ended a box's
// subscriptions before check 7 through the fields alone, keeping its counts, and called no method.
var subscriptionFiles = []string{"subscribe.go", "rendezvous_push.go"}

// Reads every function of this package for its effects, its own and those of every function of
// this package it calls, each placed at the call.
type effectReader struct {
	checked       *checkedPackage
	linkBoxes     *types.Interface
	subscriptions types.Type
	memo          map[*types.Func][]effect
	visiting      map[*types.Func]bool
	// each package-level variable initialised to a function literal, and the literal: a call through
	// the variable is a call of the literal, and its effects are placed at the call (LRI R78, N4)
	literals        map[*types.Var]*ast.FuncLit
	literalMemo     map[*types.Var][]effect
	literalVisiting map[*types.Var]bool
}

func newEffectReader(t *testing.T, checked *checkedPackage) *effectReader {
	t.Helper()
	storePackage := checked.imported(t, reflect.TypeOf((*store.LinkBoxes)(nil)).Elem().PkgPath())
	linkBoxes, ok := storePackage.Scope().Lookup("LinkBoxes").Type().Underlying().(*types.Interface)
	if !ok {
		t.Fatal("store.LinkBoxes is not an interface")
	}
	subscriptions := checked.types.Scope().Lookup("Subscriptions")
	if subscriptions == nil {
		t.Fatal("this package declares no Subscriptions")
	}
	reader := &effectReader{
		checked:         checked,
		linkBoxes:       linkBoxes,
		subscriptions:   subscriptions.Type(),
		memo:            map[*types.Func][]effect{},
		visiting:        map[*types.Func]bool{},
		literals:        map[*types.Var]*ast.FuncLit{},
		literalMemo:     map[*types.Var][]effect{},
		literalVisiting: map[*types.Var]bool{},
	}
	for _, file := range checked.syntax {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, spec := range general.Specs {
				values := spec.(*ast.ValueSpec)
				for index, name := range values.Names {
					if index >= len(values.Values) {
						continue
					}
					literal, isLiteral := ast.Unparen(values.Values[index]).(*ast.FuncLit)
					variable, isVar := checked.info.Defs[name].(*types.Var)
					if isLiteral && isVar {
						reader.literals[variable] = literal
					}
				}
			}
		}
	}

	// the registry's files, held to its methods in both directions
	methodFiles := map[string]bool{}
	methods := types.NewMethodSet(types.NewPointer(subscriptions.Type()))
	for index := range methods.Len() {
		method, ok := methods.At(index).Obj().(*types.Func)
		if !ok || checked.decls[method] == nil {
			continue
		}
		file := filepath.Base(checked.files.Position(method.Pos()).Filename)
		if !slices.Contains(subscriptionFiles, file) {
			t.Fatalf("Subscriptions.%s is declared in %s, outside the registry's files %v: a field selection there would read as a change made around its methods", method.Name(), file, subscriptionFiles)
		}
		methodFiles[file] = true
	}
	for _, file := range subscriptionFiles {
		if !methodFiles[file] {
			t.Fatalf("subscriptionFiles names %s, and no method of Subscriptions is declared in it", file)
		}
	}
	return reader
}

// Whether a position is in one of the registry's own files.
func (self *effectReader) inRegistryFile(position token.Pos) bool {
	return slices.Contains(subscriptionFiles, filepath.Base(self.checked.files.Position(position).Filename))
}

// Whether a value of this type, put in a composite literal of it, stays where these gates read it: a
// named type this package declares, whose fields the holder tests enumerate and whose methods these
// gates read. A literal of any other type, another package's above all, takes the store where they
// cannot follow it (STRUCT-HANDOFF).
func (self *effectReader) declaredHere(of types.Type) bool {
	if pointer, ok := of.(*types.Pointer); ok {
		of = pointer.Elem()
	}
	named, ok := of.(*types.Named)
	return ok && named.Obj().Pkg() == self.checked.types
}

// Whether the target of an assignment keeps a store where these gates read it: a variable local to a
// function, the blank identifier, or a field of a type this package declares. A package-level
// variable, an element of a map or a slice, or anything reached through a pointer, is not
// (PKGVAR-COLLECT).
func (self *effectReader) keepsItHere(target ast.Expr) bool {
	info := self.checked.info
	switch target := ast.Unparen(target).(type) {
	case *ast.Ident:
		if target.Name == "_" {
			return true
		}
		variable, ok := info.ObjectOf(target).(*types.Var)
		return ok && variable.Parent() != self.checked.types.Scope()
	case *ast.SelectorExpr:
		selection := info.Selections[target]
		return selection != nil && selection.Kind() == types.FieldVal && selection.Obj().Pkg() == self.checked.types
	}
	return false
}

// The effects of the function literal a package-level variable holds, each at the place in it where
// it happens.
func (self *effectReader) ofLiteral(variable *types.Var) []effect {
	if found, done := self.literalMemo[variable]; done {
		return found
	}
	literal := self.literals[variable]
	if literal == nil || self.literalVisiting[variable] {
		return nil
	}
	self.literalVisiting[variable] = true
	defer delete(self.literalVisiting, variable)
	found := self.within(literal.Body)
	self.literalMemo[variable] = found
	return found
}

// Whether a value of this type is a link box store: the interface itself, or anything that
// satisfies it.
func (self *effectReader) isLinkBoxes(of types.Type) bool {
	if of == nil {
		return false
	}
	if _, basic := of.(*types.Basic); basic {
		return false
	}
	return types.Implements(of, self.linkBoxes) || types.Implements(types.NewPointer(of), self.linkBoxes)
}

func (self *effectReader) isSubscriptions(of types.Type) bool {
	if pointer, ok := of.(*types.Pointer); ok {
		of = pointer.Elem()
	}
	return types.Identical(of, self.subscriptions)
}

// The function a call calls when that is known without running it, or nil.
func (self *effectReader) calleeOf(call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		function, _ := self.checked.info.Uses[fun].(*types.Func)
		return function
	case *ast.SelectorExpr:
		if selection := self.checked.info.Selections[fun]; selection != nil {
			if selection.Kind() == types.FieldVal || types.IsInterface(selection.Recv()) {
				return nil
			}
			function, _ := selection.Obj().(*types.Func)
			return function
		}
		function, _ := self.checked.info.Uses[fun.Sel].(*types.Func)
		return function
	}
	return nil
}

func (self *effectReader) ours(function *types.Func) bool {
	return function != nil && function.Pkg() == self.checked.types
}

// The effects of one function of this package, each at the place in it where it happens.
func (self *effectReader) of(function *types.Func) []effect {
	if found, done := self.memo[function]; done {
		return found
	}
	declaration := self.checked.decls[function]
	if declaration == nil || declaration.Body == nil || self.visiting[function] {
		return nil
	}
	self.visiting[function] = true
	defer delete(self.visiting, function)
	found := self.within(declaration.Body)
	self.memo[function] = found
	return found
}

// The effects of a piece of syntax, its own and those of the functions of this package it reaches.
func (self *effectReader) within(node ast.Node) []effect {
	info := self.checked.info
	found := []effect{}
	ast.Inspect(node, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.SelectorExpr:
			selection := info.Selections[node]
			if selection == nil {
				return true
			}
			if selection.Kind() == types.FieldVal {
				// a field of the subscription registry selected outside its own files: a change to
				// it made around its methods (LRI R78, N4; FIELD-REGISTRY-2)
				if self.isSubscriptions(selection.Recv()) && !self.inRegistryFile(node.Pos()) {
					found = append(found, effect{kind: "registry", name: "the field " + selection.Obj().Name(), at: node.Pos(),
						via: types.ExprString(node.X) + " (" + types.TypeString(selection.Recv(), types.RelativeTo(self.checked.types)) + ")"})
				}
				return true
			}
			method, ok := selection.Obj().(*types.Func)
			if !ok {
				return true
			}
			via := types.ExprString(node.X) + " (" + types.TypeString(selection.Recv(), types.RelativeTo(self.checked.types)) + ")"
			if mutates, isLinkBoxMethod := linkBoxMethodMutates[method.Name()]; isLinkBoxMethod {
				// by the method, on whatever receiver: the store, an alias of it, a parameter, an
				// interface of this package's own that declares the same method
				kind := "read"
				if mutates {
					kind = "write"
				}
				found = append(found, effect{kind: kind, name: method.Name(), at: node.Pos(), via: via})
			} else if self.isSubscriptions(selection.Recv()) && !subscriptionReads[method.Name()] {
				found = append(found, effect{kind: "registry", name: method.Name(), at: node.Pos(), via: via})
			} else if self.ours(method) {
				for _, inner := range self.of(method) {
					found = append(found, effect{kind: inner.kind, name: inner.name, at: node.Pos(), via: method.Name() + " → " + inner.via})
				}
			}
		case *ast.Ident:
			switch object := info.Uses[node].(type) {
			case *types.Func:
				// a function of this package, called or taken as a value
				if !self.ours(object) || object.Type().(*types.Signature).Recv() != nil {
					return true
				}
				for _, inner := range self.of(object) {
					found = append(found, effect{kind: inner.kind, name: inner.name, at: node.Pos(), via: object.Name() + " → " + inner.via})
				}
			case *types.Var:
				// a package-level variable holding a function literal, called or taken as a value:
				// the literal's effects, where it is used (LRI R78, N4; PKGVAR-COLLECT)
				for _, inner := range self.ofLiteral(object) {
					found = append(found, effect{kind: inner.kind, name: inner.name, at: node.Pos(), via: object.Name() + " → " + inner.via})
				}
			}
		case *ast.CallExpr:
			// a link box store handed to what these gates cannot read: a function of another
			// package, a call through a value, or a conversion to another type
			callee := self.calleeOf(node)
			conversion := info.Types[node.Fun].IsType()
			if !conversion && self.ours(callee) {
				return true
			}
			for _, argument := range node.Args {
				if self.isLinkBoxes(info.TypeOf(argument)) {
					found = append(found, effect{kind: "opaque", name: types.ExprString(node.Fun), at: node.Pos(), via: types.ExprString(argument)})
				}
			}
		// THE STORE HANDED OFF OTHERWISE THAN AS AN ARGUMENT (LRI R78, N4): put in a composite literal
		// of a type this package does not declare (STRUCT-HANDOFF), assigned to anything but a local
		// variable or a field of a type it does (PKGVAR-COLLECT), given to a package-level variable
		// as its value, or sent on a channel. Each takes it where these gates cannot follow it.
		case *ast.CompositeLit:
			if self.declaredHere(info.TypeOf(node)) {
				return true
			}
			for _, element := range node.Elts {
				value := element
				if pair, ok := element.(*ast.KeyValueExpr); ok {
					value = pair.Value
				}
				if self.isLinkBoxes(info.TypeOf(value)) {
					found = append(found, effect{kind: "opaque", name: "a composite literal of " + types.TypeString(info.TypeOf(node), types.RelativeTo(self.checked.types)),
						at: value.Pos(), via: types.ExprString(value)})
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) != len(node.Rhs) {
				return true
			}
			for index, value := range node.Rhs {
				if self.isLinkBoxes(info.TypeOf(value)) && !self.keepsItHere(node.Lhs[index]) {
					found = append(found, effect{kind: "opaque", name: "an assignment to " + types.ExprString(node.Lhs[index]), at: node.Pos(), via: types.ExprString(value)})
				}
			}
		case *ast.ValueSpec:
			for index, value := range node.Values {
				if index >= len(node.Names) || !self.isLinkBoxes(info.TypeOf(value)) {
					continue
				}
				if variable, ok := info.Defs[node.Names[index]].(*types.Var); ok && variable.Parent() == self.checked.types.Scope() {
					found = append(found, effect{kind: "opaque", name: "the package-level variable " + variable.Name(), at: value.Pos(), via: types.ExprString(value)})
				}
			}
		case *ast.SendStmt:
			if self.isLinkBoxes(info.TypeOf(node.Value)) {
				found = append(found, effect{kind: "opaque", name: "a send on " + types.ExprString(node.Chan), at: node.Pos(), via: types.ExprString(node.Value)})
			}
		}
		return true
	})
	return found
}

// EVERY LINK BOX WRITE THIS PACKAGE CAN MAKE IS MADE BY ITS OWN ARM, held as
// TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate holds [store.Store]. The method set
// comes off the interface by reflection, so a method added to it fails here unclassified. A write,
// found by its method on whatever receiver, is permitted in the function of the one arm that owns
// it and nowhere else, which rules out a helper that writes; no link box store is handed to code
// this gate cannot read; and every method of the store is called by something. The receivers, by
// spelling and type, and the store-typed fields, are printed.
func TestEveryLinkBoxWriteThisPackageCanMakeIsMadeByItsOwnArm(t *testing.T) {
	interfaceType := reflect.TypeOf((*store.LinkBoxes)(nil)).Elem()
	declared := []string{}
	for index := range interfaceType.NumMethod() {
		name := interfaceType.Method(index).Name
		declared = append(declared, name)
		if _, classified := linkBoxMethodMutates[name]; !classified {
			t.Fatalf("store.LinkBoxes declares %s and linkBoxMethodMutates does not say whether it writes", name)
		}
	}
	for name := range linkBoxMethodMutates {
		if !slices.Contains(declared, name) {
			t.Fatalf("linkBoxMethodMutates classifies %s and store.LinkBoxes no longer declares it", name)
		}
	}

	checked := typeCheckThisPackage(t)
	reader := newEffectReader(t, checked)
	storePath := interfaceType.PkgPath()

	// THE TWO HOLDER TESTS PARTITION THE STORE'S HOLDERS, by type. Every struct field in this
	// package whose type comes from package store is a store.Store, held by
	// TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate, or a store.LinkBoxes, held
	// here; a field of any other type from store is held by neither, and fails by name.
	heldBy := map[string]string{
		"Store":     "TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate",
		"LinkBoxes": "TestEveryLinkBoxWriteThisPackageCanMakeIsMadeByItsOwnArm",
	}
	storeFields := map[string][]string{}
	for _, name := range checked.types.Scope().Names() {
		named, ok := checked.types.Scope().Lookup(name).Type().(*types.Named)
		if !ok {
			continue
		}
		structure, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for index := range structure.NumFields() {
			field := structure.Field(index)
			fieldType := field.Type()
			if pointer, ok := fieldType.(*types.Pointer); ok {
				fieldType = pointer.Elem()
			}
			fieldNamed, ok := fieldType.(*types.Named)
			if !ok || fieldNamed.Obj().Pkg() == nil || fieldNamed.Obj().Pkg().Path() != storePath {
				continue
			}
			storeFields[fieldNamed.Obj().Name()] = append(storeFields[fieldNamed.Obj().Name()], name+"."+field.Name())
		}
	}
	t.Logf("struct fields of a type from package store, by type: %v", storeFields)
	for typeName, fields := range storeFields {
		if _, held := heldBy[typeName]; !held {
			t.Fatalf("this package holds a store.%s in %v, and neither holder test holds that type", typeName, fields)
		}
	}
	for typeName, test := range heldBy {
		if len(storeFields[typeName]) == 0 {
			t.Fatalf("%s holds store.%s, and no struct field in this package is one", test, typeName)
		}
	}

	// every function's own link box calls, each in the function whose syntax holds it
	calls := map[string][]string{}
	receivers := map[string]bool{}
	for function, declaration := range checked.decls {
		if declaration.Body == nil {
			continue
		}
		for _, found := range reader.within(declaration.Body) {
			// a call of a helper is not the helper's own call: only the effects whose `via` is a
			// receiver, written in this function, are this function's
			if strings.Contains(found.via, " → ") {
				continue
			}
			switch found.kind {
			case "opaque":
				t.Fatalf("%s hands the link box store %s to %s at %s, which these gates cannot read",
					function.Name(), found.via, found.name, checked.at(found.at))
			case "read", "write":
				calls[found.name] = append(calls[found.name], function.Name())
				receivers[found.via] = true
				if found.kind == "write" && function.Name() != linkBoxWriteArm[found.name] {
					t.Fatalf("store.LinkBoxes.%s is called from %s at %s through %s, and a link box write belongs to %s alone",
						found.name, function.Name(), checked.at(found.at), found.via, linkBoxWriteArm[found.name])
				}
			}
		}
	}
	// AND OUTSIDE EVERY FUNCTION (LRI R78, N4): a function literal in a package-level declaration is
	// code of no arm, so a write there is a write outside every arm, and a store handed off there is
	// handed where these gates cannot follow it (PKGVAR-COLLECT)
	outside := 0
	for _, file := range checked.syntax {
		for _, declaration := range file.Decls {
			if _, isFunction := declaration.(*ast.FuncDecl); isFunction {
				continue
			}
			for _, found := range reader.within(declaration) {
				if strings.Contains(found.via, " → ") {
					continue
				}
				outside++
				switch found.kind {
				case "opaque":
					t.Fatalf("a package-level declaration hands the link box store %s to %s at %s, which these gates cannot read",
						found.via, found.name, checked.at(found.at))
				case "write":
					t.Fatalf("store.LinkBoxes.%s is called in a package-level declaration at %s through %s, outside every arm, and a link box write belongs to %s alone",
						found.name, checked.at(found.at), found.via, linkBoxWriteArm[found.name])
				case "read":
					calls[found.name] = append(calls[found.name], "a package-level declaration")
					receivers[found.via] = true
				}
			}
		}
	}
	t.Logf("effects of package-level declarations, of their own: %d", outside)
	unused := []string{}
	for _, name := range declared {
		if len(calls[name]) == 0 {
			unused = append(unused, name)
		}
	}
	t.Logf("the receivers the link box methods are called on: %v", sorted(receivers))
	t.Logf("calls, by method: %v", calls)
	if len(unused) != 0 {
		t.Fatalf("store.LinkBoxes declares %v and this package never calls them", unused)
	}
}

// THE LIBRARY'S RENDEZVOUS SURFACE, AND WHAT OF IT THIS PACKAGE MAY CALL: an allowlist, one row per
// exported function of the record layer's rendezvous file, with its reason. The rows are held to
// that file in both directions, so a function the library adds fails here until it has a row, and
// a row the library dropped fails as stale. A row with no callers is one no function here may call.
var rendezvousSurface = map[string]struct {
	callers []string
	why     string
}{
	"VerifyRendezvousRegister": {[]string{"RendezvousRegister"}, "§5.1.2 check 7 on Register: register_auth under the collect key the request carries"},
	"VerifyRendezvousOpen":     {[]string{"RendezvousOpen"}, "check 7 on Open: open_auth under the pinned deposit key"},
	"VerifyRendezvousDeposit":  {[]string{"RendezvousDeposit"}, "check 7 on Deposit: deposit_auth under the pinned deposit key, over H(deposit_ct)"},
	"VerifyRendezvousCollect":  {[]string{"RendezvousCollect"}, "check 7 on Collect: collect_auth under the pinned collect key"},
	"VerifyRendezvousRetire":   {[]string{"RendezvousRetire"}, "check 7 on Retire: retire_auth under the pinned collect key"},
	"RendezvousKeyIsAcceptable": {[]string{"linkBoxRegistrationShaped"},
		"Register's check 3: the library's small-order rule, which every verifier applies first, so that no box is stored under a key nobody could use (LRI R72, R73); in A-1's block since A-38"},
	"RendezvousRegisterPreimage": {nil, "the client's half, signed over; it panics on what it refuses, and the server builds no preimage"},
	"RendezvousOpenPreimage":     {nil, "the client's half"},
	"RendezvousDepositPreimage":  {nil, "the client's half"},
	"RendezvousCollectPreimage":  {nil, "the client's half"},
	"RendezvousRetirePreimage":   {nil, "the client's half"},
	"RendezvousId":               {nil, "the link code's derivation; the server holds no code and is handed the id"},
	"DepositVerifyKey":           {nil, "the link code's derivation; the server is handed the key at registration"},
	"LinkCardBytes":              {nil, "held equal to store.LinkCardBytes by TestTheLinkBoxSizesAreTheLibrarys"},
	"LinkDepositBytes":           {nil, "held equal to store.LinkDepositBytes by TestTheLinkBoxSizesAreTheLibrarys"},
}

// Each arm, and the one verifier of the library's it answers to.
var rendezvousArmVerifier = map[string]string{
	"RendezvousRegister": "VerifyRendezvousRegister",
	"RendezvousOpen":     "VerifyRendezvousOpen",
	"RendezvousDeposit":  "VerifyRendezvousDeposit",
	"RendezvousCollect":  "VerifyRendezvousCollect",
	"RendezvousRetire":   "VerifyRendezvousRetire",
}

// The exported functions of the record layer's rendezvous file: the file that declares the
// register verifier, read out of the library rather than named here.
func recordLayerRendezvousSurface(t *testing.T) map[string]bool {
	t.Helper()
	fileSet, libraryFiles := parseGoDir(t, recordLayerDir(t), false)
	surface := map[string]bool{}
	for _, file := range libraryFiles {
		declared, ours := []string{}, false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !function.Name.IsExported() {
				continue
			}
			declared = append(declared, function.Name.Name)
			if function.Name.Name == "VerifyRendezvousRegister" {
				ours = true
			}
		}
		if ours {
			if len(surface) != 0 {
				t.Fatalf("two files of the record layer declare VerifyRendezvousRegister; the second is %s", fileSet.File(file.Pos()).Name())
			}
			for _, name := range declared {
				surface[name] = true
			}
		}
	}
	if len(surface) == 0 {
		t.Fatal("no file of the record layer declares VerifyRendezvousRegister, so this gate read no rendezvous surface")
	}
	return surface
}

// EVERY RENDEZVOUS ARM VERIFIES ITS SIGNATURE THROUGH THE LIBRARY BEFORE IT CHANGES ANYTHING (§5.1.2:
// "no transaction is opened and no row is allocated before check 7 has passed"; Spec A §12.1's A-1;
// LRI R75, T1 and T2), and nothing here reaches the library's rendezvous surface outside the
// allowlist above.
//
// Each arm calls its own verifier once and no other's, and the call is the whole condition of an `if`
// that is a STATEMENT OF THE ARM'S OWN BODY, with no init and no else, ending in a return: a false
// answer ends the arm, and every statement after it runs only on a true one. A verifier inside a
// branch decides nothing on the branch's other side, which is BRANCH-COLLECT, and is refused here
// whatever the branch tests. Every effect the arm has, resolved by type and through every helper of
// this package it calls, is then held to a place: a link box write, a change to the subscription
// registry, or a link box store handed to code this gate cannot read, only after that `if`;
// before it, Register reads nothing of the store at all, and the other four only Q17. No arm holds
// a goto. Every reach into the surface is made by a function its row names, by type, so that an
// alias of the library's package, or a function value taken from it, is the reach it is.
//
// MR6, Open without open_auth, fails here as well as in the arms' own test, whether its call is
// removed or kept and made to decide nothing, and so does Register's small-order call dropped;
// BRANCH-COLLECT, ALIAS-COLLECT and PARAM-COLLECT fail here and in cmd/message-server's behavioural
// test of every unauthorized request. So do the delta review's three (LRI R78, N4): PKGVAR-COLLECT,
// a store put in a package-level variable and written through a package-level function literal;
// STRUCT-HANDOFF, a store handed to another package inside a composite literal; and FIELD-REGISTRY-2,
// a box's subscriptions ended through the registry's fields, keeping its counts.
func TestEveryRendezvousArmVerifiesThroughTheLibraryBeforeItWrites(t *testing.T) {
	surface := recordLayerRendezvousSurface(t)
	for name := range surface {
		if _, listed := rendezvousSurface[name]; !listed {
			t.Fatalf("the record layer's rendezvous file exports %s, and rendezvousSurface has no row saying whether this package may call it", name)
		}
	}
	for name := range rendezvousSurface {
		if !surface[name] {
			t.Fatalf("rendezvousSurface has a row for %s, and the record layer's rendezvous file no longer exports it", name)
		}
	}
	for arm, verifier := range rendezvousArmVerifier {
		if row := rendezvousSurface[verifier]; !slices.Equal(row.callers, []string{arm}) {
			t.Fatalf("%s answers to %s, and that verifier's row names %v", arm, verifier, row.callers)
		}
	}

	checked := typeCheckThisPackage(t)
	reader := newEffectReader(t, checked)
	library := checked.imported(t, recordLayerImportPath(t))

	// every reach into the surface, by the function whose syntax holds it
	reached := map[string][]string{}
	for function, declaration := range checked.decls {
		if declaration.Body == nil {
			continue
		}
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok {
				return true
			}
			object, isFunction := checked.info.Uses[identifier].(*types.Func)
			if !isFunction || object.Pkg() != library || object.Type().(*types.Signature).Recv() != nil || !surface[object.Name()] {
				return true
			}
			reached[function.Name()] = append(reached[function.Name()], object.Name())
			if !slices.Contains(rendezvousSurface[object.Name()].callers, function.Name()) {
				t.Fatalf("%s reaches the library's %s at %s, and its row allows %v: %s",
					function.Name(), object.Name(), checked.at(identifier.Pos()), rendezvousSurface[object.Name()].callers, rendezvousSurface[object.Name()].why)
			}
			return true
		})
	}
	// and none outside a function: a package-level value taken from the surface is a reach with no
	// caller to hold it to
	for _, file := range checked.syntax {
		for _, declaration := range file.Decls {
			if _, isFunction := declaration.(*ast.FuncDecl); isFunction {
				continue
			}
			ast.Inspect(declaration, func(node ast.Node) bool {
				if identifier, ok := node.(*ast.Ident); ok {
					if object, isFunction := checked.info.Uses[identifier].(*types.Func); isFunction && object.Pkg() == library && surface[object.Name()] {
						t.Fatalf("a package-level declaration reaches the library's %s at %s", object.Name(), checked.at(identifier.Pos()))
					}
				}
				return true
			})
		}
	}
	t.Logf("reaches into the library's rendezvous surface, by function: %v", reached)
	for name, row := range rendezvousSurface {
		for _, caller := range row.callers {
			if !slices.Contains(reached[caller], name) {
				t.Fatalf("%s's row names %s as its caller, and %s does not reach it: %s", name, caller, caller, row.why)
			}
		}
	}

	for arm, verifierName := range rendezvousArmVerifier {
		function, declaration := checked.handlerMethod(t, arm)
		verifier, ok := library.Scope().Lookup(verifierName).(*types.Func)
		if !ok {
			t.Fatalf("the library declares no function %s", verifierName)
		}

		// every call in the arm of any of the five verifiers, and of its own
		own := []*ast.CallExpr{}
		anyVerifier := []string{}
		ast.Inspect(declaration.Body, func(node ast.Node) bool {
			if branch, ok := node.(*ast.BranchStmt); ok && branch.Tok == token.GOTO {
				t.Fatalf("%s holds a goto at %s; an arm's check order is its statements' order, and a goto is a way around it", arm, checked.at(branch.Pos()))
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee := reader.calleeOf(call)
			if callee == nil || callee.Pkg() != library || !strings.HasPrefix(callee.Name(), "VerifyRendezvous") {
				return true
			}
			anyVerifier = append(anyVerifier, callee.Name())
			if callee == verifier {
				own = append(own, call)
			}
			return true
		})
		if len(own) != 1 || len(anyVerifier) != 1 {
			t.Fatalf("%s calls the rendezvous verifiers %v, want %s once and no other", arm, anyVerifier, verifierName)
		}

		// the if that decides: a statement of the arm's own body
		var decides *ast.IfStmt
		for _, statement := range declaration.Body.List {
			candidate, ok := statement.(*ast.IfStmt)
			if !ok {
				continue
			}
			if negation, ok := candidate.Cond.(*ast.UnaryExpr); ok && negation.Op == token.NOT && ast.Unparen(negation.X) == own[0] {
				decides = candidate
			}
		}
		if decides == nil {
			t.Fatalf("%s calls %s at %s, and not as the whole condition of an if that is a statement of its own body: a verifier nested in a branch decides nothing on the branch's other side, and one that is part of a condition decides nothing at all",
				arm, verifierName, checked.at(own[0].Pos()))
		}
		if decides.Init != nil || decides.Else != nil || len(decides.Body.List) == 0 {
			t.Fatalf("%s's verifier if at %s has an init, an else or no body", arm, checked.at(decides.Pos()))
		}
		if _, returns := decides.Body.List[len(decides.Body.List)-1].(*ast.ReturnStmt); !returns {
			t.Fatalf("%s's verifier if at %s does not end in a return, so a signature that does not verify does not end the arm", arm, checked.at(decides.Pos()))
		}

		before, after := []string{}, []string{}
		for _, found := range reader.of(function) {
			switch {
			case found.at >= decides.End():
				after = append(after, found.String())
			case found.kind == "read" && (found.name == "LinkBox" && arm != "RendezvousRegister"):
				before = append(before, found.String())
			case found.kind == "read":
				t.Fatalf("%s reads the store before its verifier: %s at %s (Register reads nothing before check 7, and the other four only Q17)",
					arm, found, checked.at(found.at))
			default:
				t.Fatalf("%s makes a %s before its verifier has passed, or inside its if: %s at %s, and its verifier's if is at %s",
					arm, found.kind, found, checked.at(found.at), checked.at(decides.Pos()))
			}
		}
		t.Logf("%s: %s at %s, a statement of its body; before it %v; after it %v", arm, verifierName, checked.at(decides.Pos()), before, after)
	}
}
