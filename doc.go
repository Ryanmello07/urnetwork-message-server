// The root of the message-server module. It holds no code and nothing imports it.
//
// What lives here is the dependency rule of spec B §2.2, in deps_test.go. That rule is a
// property of the whole module rather than of any one package in it, and a gate that lived
// inside api or store would be a gate that stops running the day somebody deletes that
// package. It sits at the root, where ./... is the whole module by construction.
package messageserver
