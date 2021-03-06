
# Tutorial 0: Getting started with libkazv

## Prerequisites

We will assume all of the following:

1. You know the basis about a Unix-like shell and its utilities.

2. You have some knowledge about C++. You know what [`auto`][auto-cppref] means in
   post-c++11 programs. You know the basic input/output in the standard library.
   You know what a [namespace][ns-cppref] is.

3. You have libkazv installed. If you installed libkazv from a pre-built package in
   a binary-based distribution, you have the related development packages installed,
   if applicable. You have CMake, G++ and other related build tools. Your G++ supports
   the standard gnu++17. Compilers other than G++ are not tested and cannot be
   guaranteed to work.

4. You have a matrix account on a matrix homeserver that you can connect to. It is
   not your main account for daily use (to prevent accidental mis-operations). It
   preferrably has joined a small number of rooms.


[auto-cppref]: https://en.cppreference.com/w/cpp/language/auto
[ns-cppref]: https://en.cppreference.com/w/cpp/language/namespace

## Goals

By completing this tutorial, we would like you to:

1. know how to create a basic program with libkazv.
2. know how to login with your homeserver address, account and password.
3. understand what a Promise is, and know how to use `then()` to do another
   thing after a Promise resolves.
4. understand that the dispatched actions will be run only after you start
   the event loop.

If you found you did not accomplish the above after the tutorial,
or if you had any questions, please do not hesitate to contact us.

## What you need to do

We will use a minimal tutorial to tell how to use libkazv.

The code is in `tutorial0.cpp` in this directory.

Use

```bash
mkdir -pv build && cd build
cmake .. -DCMAKE_PREFIX_PATH=<libkazv's CMAKE_INSTALL_PREFIX>
make tutorial0
./tutorial0
```

to build and run the code.

Upon running, you will be asked about your homeserver, username and password.
After entering these details (e.g. `https://tusooa.xyz` for homeserver,
`exampleuser` for username and `examplepassword` for password), it will
try to login with these credentials. If the login fails, it prints an error
message and exits. If the login succeeds, it will start syncing indefinitely.

Press Ctrl-c to end the program.

## Code explained

```
auto io = ...;
auto jh = Kazv::CprJobHandler{...};
auto ee = Kazv::LagerStoreEventEmitter{...};

auto sdk = Kazv::makeSdk(
    Kazv::SdkModel{},
    jh,
    ee,
    Kazv::AsioPromiseHandler{io.get_executor()},
    zug::identity
    );
```

These creates the sdk. `io` is `boost::asio::io_context`, which we will base our event loop
upon. `Kazv::CprJobHandler` is a class that actually performs network requests.
`Kazv::LagerStoreEventEmitter` is a class that emits *triggers* that you can listen to.

`Kazv::makeSdk` puts everything together and gives you an `Sdk` object to operate on.

- `Kazv::SdkModel{}` is the initial state. We now use a default-constructed one.
- `Kazv::AsioPromiseHandler` is a class to assist describing actions in event loops.
  We will get back to this later.
- `zug::identity` is not yet relevant here.

```
auto client = sdk.client();
```

`Sdk` is a wrapper class. Most of the real operations are done via `Client`.
We obtain an instance of it here.

```
client.passwordLogin(homeserver, username, password, deviceName)
    .then([=](auto status) {
        if (! status.success()) {
            std::cerr << "Login failed" << std::endl;
            std::exit(1);
        }
        client.startSyncing();
    });
```

A lot of interesting things here.

`client.passwordLogin()` *dispatches* an action to login with the credentials you
entered. It returns a `Promise` that resolves when the login is successful, or when
there is an error.

A `Promise` represents a value that will be available *later*, and allow you to use
it via the `then` chaining method. This is achieved by a *Promise handler*, such as
the `Kazv::AsioPromiseHandler` we used before. We call a `Promise` *resolved* when the value
contained is available. If you have used JavaScript before, this construct
may be familiar to you. Note that here the type of the value in the `Promise` is fixed:
it is always an `EffectStatus`. This is due to the limit of the language. The `then`
method takes a function that can take an `EffectStatus` and return either `void`, or
`EffectStatus`, or `Promise`.

`EffectStatus` has a method named `success()`, and you can use it to determine whether
the action you dispatched succeeded or not. Here, if it fails, we simply print a failure
message and terminate the program. If it succeeds, we call `client.startSyncing()`,
which will dispatch SyncAction indefinitely, parse the response, and update the state of
the sdk. Its return type is also a `Promise` (and it resolves when the *initial* sync
finishes), so we can write `return client.startSyncing();`
instead. However, as there are no more chaining `then()`s, it is not very useful to
do so.

Note that we use `[=]` as the lambda capture, and we do not use the `mutable` keyword--
Yes, `Client` is a copyable type, and every method of `Client` is `const`, even those
that dispatch actions. This is a useful feature enabled by the value oriented
design.

> A possible pitfall: In an instance method, `[=]` will implicitly capture
> the current instance by reference, if you use a member in the lambda. Try to avoid
> using lambdas that captures the current instance by reference in an async callback
> function (like `then()`):
>
> ```
> SomeClass::someMethod()
> {
>     m_client.someOperation()
>         .then([=] {
>             // Bad
>             m_client.someOtherOperation();
>         });
> }
> ```
>
> The code above is bad because, it is possible that the instance of `SomeClass` may
> have been destroyed by the time the callback is actually run. And thus, `m_client`,
> which is acutally `(capturedThis)->m_client`, is a dereferencing of a dangling
> pointer. This will give you a segmentation fault as a result. It is suggested to
> explicitly capture `m_client` by changing `[=]` to `[m_client=m_client]`.

```
io.run();
```

Start the event loop. Simple. The dispatched actions will not be run till this call.
