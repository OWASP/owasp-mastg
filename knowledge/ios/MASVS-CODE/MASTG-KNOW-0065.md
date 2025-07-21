---
masvs_category: MASVS-CODE
platform: ios
title: Exception Handling
---

Exceptions often occur after an application enters an abnormal or erroneous state.
Testing exception handling is about making sure that the application will handle the exception and get into a safe state without exposing any sensitive information via its logging mechanisms or the UI.

Bear in mind that exception handling in Objective-C is quite different from exception handling in Swift. Bridging the two approaches in an application that is written in both legacy Objective-C code and Swift code can be problematic.

## Exception Handling in Objective-C

Objective-C has two types of errors:

**NSException:**

`NSException` is used to handle programming and low-level errors (e.g., division by 0 and out-of-bounds array access).
An `NSException` can either be raised by `raise` or thrown with `@throw`. Unless caught, this exception will invoke the unhandled exception handler, with which you can log the statement (logging will halt the program). `@catch` allows you to recover from the exception if you're using a `@try`-`@catch`-block:

```objectivec
 @try {
    //do work here
 }

@catch (NSException *e) {
    //recover from exception
}

@finally {
    //cleanup
```

Bear in mind that using `NSException` comes with memory management pitfalls: you need to [clean up allocations](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/RaisingExceptions.html#//apple_ref/doc/uid/20000058-BBCCFIBF "Raising exceptions") from the try block that are in the [finally block](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/Exceptions/Tasks/HandlingExceptions.html "Handling Exceptions"). Note that you can promote `NSException` objects to `NSError` by instantiating an `NSError` in the `@catch` block.

**NSError:**

`NSError` is used for all other types of [errors](https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ProgrammingWithObjectiveC/ErrorHandling/ErrorHandling.html "Dealing with Errors"). Some Cocoa framework APIs provide errors as objects in their failure callback in case something goes wrong; those that don't provide them pass a pointer to an `NSError` object by reference. It is a good practice to provide a `BOOL` return type to the method that takes a pointer to an `NSError` object to indicate success or failure. If there's a return type, make sure to return `nil` for errors. If `NO` or `nil` is returned, it allows you to inspect the error/reason for failure.

## Exception Handling in Swift

Exception handing in Swift (2 - 5) is quite different. The try-catch block is not there to handle `NSException`. The block is used to handle errors that conform to the `Error` (Swift 3) or `ErrorType` (Swift 2) protocol. This can be challenging when Objective-C and Swift code are combined in an application. Therefore, `NSError` is preferable to `NSException` for programs written in both languages. Furthermore, error-handling is opt-in in Objective-C, but `throws` must be explicitly handled in Swift. To convert error-throwing, look at the [Apple documentation](https://developer.apple.com/library/content/documentation/Swift/Conceptual/BuildingCocoaApps/AdoptingCocoaDesignPatterns.html "Adopting Cocoa Design Patterns").
Methods that can throw errors use the `throws` keyword. The `Result` type represents a success or failure, see [Result](https://developer.apple.com/documentation/swift/result), [How to use Result in Swift 5](https://www.hackingwithswift.com/articles/161/how-to-use-result-in-swift) and [The power of Result types in Swift](https://www.swiftbysundell.com/posts/the-power-of-result-types-in-swift). There are four ways to [handle errors in Swift](https://developer.apple.com/library/content/documentation/Swift/Conceptual/Swift_Programming_Language/ErrorHandling.html "Error Handling in Swift"):

- Propagate the error from a function to the code that calls that function. In this situation, there's no `do-catch`; there's only a `throw` throwing the actual error or a `try` to execute the method that throws. The method containing the `try` also requires the `throws` keyword:

```default
func dosomething(argumentx:TypeX) throws {
    try functionThatThrows(argumentx: argumentx)
}
```

- Handle the error with a `do-catch` statement. You can use the following pattern:

  ```default
  func doTryExample() {
      do {
          try functionThatThrows(number: 203)
      } catch NumberError.lessThanZero {
          // Handle number is less than zero
      } catch let NumberError.tooLarge(delta) {
          // Handle number is too large (with delta value)
      } catch {
          // Handle any other errors
      }
  }

  enum NumberError: Error {
      case lessThanZero
      case tooLarge(Int)
      case tooSmall(Int)
  }

  func functionThatThrows(number: Int) throws -> Bool {
      if number < 0 {
          throw NumberError.lessThanZero
      } else if number < 10 {
          throw NumberError.tooSmall(10 - number)
      } else if number > 100 {
          throw NumberError.tooLarge(100 - number)
      } else {
          return true
      }
  }
  ```

- Handle the error as an optional value:

  ```default
      let x = try? functionThatThrows()
      // In this case the value of x is nil in case of an error.
  ```

- Use the `try!` expression to assert that the error won't occur.
- Handle the generic error as a `Result` return:

```default
enum ErrorType: Error {
    case typeOne
    case typeTwo
}

func functionWithResult(param: String?) -> Result<String, ErrorType> {
    guard let value = param else {
        return .failure(.typeOne)
    }
    return .success(value)
}

func callResultFunction() {
    let result = functionWithResult(param: "OWASP")

    switch result {
    case let .success(value):
        // Handle success
    case let .failure(error):
        // Handle failure (with error)
    }
}
```

- Handle network and JSON decoding errors with a `Result` type:

```default
struct MSTG: Codable {
    var root: String
    var plugins: [String]
    var structure: MSTGStructure
    var title: String
    var language: String
    var description: String
}

struct MSTGStructure: Codable {
    var readme: String
}

enum RequestError: Error {
    case requestError(Error)
    case noData
    case jsonError
}

func getMSTGInfo() {
    guard let url = URL(string: "https://raw.githubusercontent.com/OWASP/mastg/master/book.json") else {
        return
    }

    request(url: url) { result in
        switch result {
        case let .success(data):
            // Handle success with MSTG data
            let mstgTitle = data.title
            let mstgDescription = data.description
        case let .failure(error):
            // Handle failure
            switch error {
            case let .requestError(error):
                // Handle request error (with error)
            case .noData:
                // Handle no data received in response
            case .jsonError:
                // Handle error parsing JSON
            }
        }
    }
}

func request(url: URL, completion: @escaping (Result<MSTG, RequestError>) -> Void) {
    let task = URLSession.shared.dataTask(with: url) { data, _, error in
        if let error = error {
            return completion(.failure(.requestError(error)))
        } else {
            if let data = data {
                let decoder = JSONDecoder()
                guard let response = try? decoder.decode(MSTG.self, from: data) else {
                    return completion(.failure(.jsonError))
                }
                return completion(.success(response))
            }
        }
    }
    task.resume()
}
```
