# Matasano Crypto Challenges

This a set of solutions to the [cryptopals](http://cryptopals.com) challenges written in Go.

## Running the solutions

Challenges are implemented as tests with names in the format TestChallengeN where N is the challenge number.

Run all challenges with `go test .`, or a specific challenge `go test -test.run TestChallengeN .` 

## Godep

I've vendored the testify library used for assertions with [Godep](https://github.com/tools/godep) because it occasionally changes and can break assertions. You can use the vendored code by installing Godep and running `godep go test .`
