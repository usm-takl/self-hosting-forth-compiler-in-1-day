test() {
    echo test: "$1"
    sh -c "$1" > tests/stdout
    if [ $? -a "$(cat tests/stdout)" != "$2" ]; then
        echo failed
        echo "expected:" $2
        echo "actual  :" $(cat tests/stdout)
        rm -f tests/stdout
        rm -f tests/test.exe
        exit 1
    fi
    echo ok
    rm -f tests/stdout
    rm -f tests/test.exe
}

# test forth0.exe
test "cat core.ft tests/forth0begin.ft tests/1-2-plus-dot.ft tests/forth0end.ft | ./forth0" "3"
test "cat core.ft tests/forth0begin.ft tests/branch.ft tests/forth0end.ft | ./forth0" "2459"
test "cat core.ft tests/forth0begin.ft tests/loop.ft tests/forth0end.ft | ./forth0" "9876543210"

test "cat core.ft msvcrt.ft tests/1-2-plus-dot.ft | ./forth0 tests/test.exe && tests/test.exe" "3"
test "cat core.ft msvcrt.ft tests/branch.ft | ./forth0 tests/test.exe && tests/test.exe" "2459"
test "cat core.ft msvcrt.ft tests/loop.ft | ./forth0 tests/test.exe && tests/test.exe" "9876543210"

# test forth1.exe
test "echo tests/1-2-plus-dot.ft -- main | ./forth1" "3"
test "echo tests/branch.ft -- main | ./forth1" "2459"
test "echo tests/loop.ft -- main | ./forth1" "9876543210"

test "echo core.ft msvcrt.ft tests/1-2-plus-dot.ft --save tests/test.exe | ./forth1 && tests/test" "3"
test "echo core.ft msvcrt.ft tests/branch.ft --save tests/test.exe | ./forth1 && tests/test" "2459"
test "echo core.ft msvcrt.ft tests/loop.ft --save tests/test.exe | ./forth1 && tests/test" "9876543210"

# test forth2.exe
test "echo tests/1-2-plus-dot.ft -- main | ./forth2" "3"
test "echo tests/branch.ft -- main | ./forth2" "2459"
test "echo tests/loop.ft -- main | ./forth2" "9876543210"

test "echo core.ft msvcrt.ft tests/1-2-plus-dot.ft --save tests/test.exe | ./forth2 && tests/test" "3"
test "echo core.ft msvcrt.ft tests/branch.ft --save tests/test.exe | ./forth2 && tests/test" "2459"
test "echo core.ft msvcrt.ft tests/loop.ft --save tests/test.exe | ./forth2 && tests/test" "9876543210"

# test forth3.exe
test "diff forth2.exe forth3.exe; echo $?" "0"

echo
echo all tests passed
