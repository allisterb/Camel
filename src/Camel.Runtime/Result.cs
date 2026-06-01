namespace Camel;

using System;
using System.Linq;
using System.Threading.Tasks;

public enum ResultType
{
    Success,
    Failure
}

public struct Result<T>
{
    public Result(ResultType type, T? value = default, string? message = null, Exception? exception = null)
    {
        this.Type = type;
        this._Value = value;
        this.Message = message;
        this.Exception = exception;
    }

    public bool IsSuccess => this.Type == ResultType.Success;

    public T Value => IsSuccess ? _Value! : throw new InvalidOperationException("The operation did not succced.");

    public bool Succeeded(out Result<T> r)
    {
        r = this;
        return IsSuccess;
    }

    public Result<U> Map<U>(Func<T, U> func)
    {
        if (IsSuccess)
        {
            return Result<U>.Success(func(Value));
        }
        else
        {
            return Result<U>.Failure(Message, Exception);
        }
    }

    public static Result<T> Success(T value) => new Result<T>(ResultType.Success, value);

    public static Result<T> Failure(string? message, Exception? exception = null) => new Result<T>(ResultType.Failure, message: message, exception: exception);

    public static Task<Result<T>> ExecuteAsync(Task<T> task, string? errorMessage = null)
        => task.ContinueWith(t =>
           {
               if (t.IsCompletedSuccessfully)
               {
                   return Success(t.Result);
               }
               else if (t.IsFaulted)
               {
                   return Failure(errorMessage, t.Exception);
               }
               else
               {
                   return Failure("The task was canceled or did not complete.");
               }
           });
       
    public ResultType Type;
    public T? _Value;
    public string? Message;
    public Exception? Exception;
}

public static class Result
{
    public static Result<T> Success<T>(T value) => new Result<T>(ResultType.Success, value);

    public static Result<T> SuccessWithInfo<T>(T value, string message, params object[] args)
    {
        Runtime.Info(message, args);
        return Success(value);
    }
    public static Result<T> Failure<T>(string? message, Exception? exception = null) => new Result<T>(ResultType.Failure, message: message, exception: exception);

    public static Result<T> Failure<T>(string message, params object[] args) => new Result<T>(ResultType.Failure, message: string.Format(message, args));

    public static Result<T> Failure<T>(string message, Exception exception, params object[] args) => new Result<T>(ResultType.Failure, exception: exception, message: string.Format(message, args));

    public static Result<T> FailureWithError<T>(string message, Exception? exception = null)
    {
        if (exception is not null)
        {
            Runtime.Error(exception, message);
            return Failure<T>(message, exception);
        }
        else
        {
            Runtime.Error(message);
            return Failure<T>(message);
        }
    }

    public static Result<T> FailureWithError<T>(string message, params object[] args)
    {

        Runtime.Error(message, args);
        return Failure<T>(message, args);

    }

    public static Result<T> FailureWithError<T>(string message, Exception exception, params object[] args)
    {
        Runtime.Error(exception, message, args);
        return Failure<T>(message, exception, args);
    }

    public static async Task<Result<T>> ExecuteAsync<T>(Task<T> task, string? infoMessage = null, string? errorMessage = null, Func<T, string>? val = null, params object[] args)
    {
        var r = await Result<T>.ExecuteAsync(task, errorMessage);
        if (r.IsSuccess && val is not null)
        {
            args = args.Append(val(r.Value)).ToArray();
        }
        if (r.IsSuccess && !string.IsNullOrEmpty(infoMessage))
        {
            Runtime.Info(string.Format(infoMessage, args));
        }
        else if (!r.IsSuccess && !string.IsNullOrEmpty(errorMessage) && r.Exception is not null)
        {
            if (!string.IsNullOrEmpty(errorMessage)) errorMessage = errorMessage + $":{r.Message}";
            Runtime.Error(r.Exception, errorMessage, args);
        }

        else if (!r.IsSuccess && !string.IsNullOrEmpty(errorMessage))
        {
            if (!string.IsNullOrEmpty(errorMessage)) errorMessage = errorMessage + $":{r.Message}";
            Runtime.Error(errorMessage, args);
        }

        else if (!r.IsSuccess && !string.IsNullOrEmpty(r.Message))
        {
            Runtime.Error(r.Message);
        }
        return r;
    }

    public static Task<Result<None>> ExecuteAsync(Task task, string? errorMessage = null)
        => task.ContinueWith(t =>
        {
            if (t.IsCompletedSuccessfully)
            {
                return Result<None>.Success(None.Value);
            }
            else if (t.IsFaulted)
            {
                return Result<None>.Success(None.Value);
            }
            else
            {
                return Failure<None>("The task was canceled or did not complete.");
            }
        });
   
    public static T ResultOrFail<T>(Result<T> result) => result.IsSuccess ? result.Value : throw new Exception("The operation failed: " + result.Message, result.Exception);

    public static async Task<T> ResultOrFail<T>(Task<Result<T>> result) => (await result).IsSuccess ? result.Result.Value : throw new Exception("The operation failed: " + result.Result.Message, result.Result.Exception);

    public static bool Succeeded<T>(Result<T> result, out Result<T> r)
    {
        r = result;
        return r.IsSuccess;
    }

    public static Task AsyncException<E>() where E : Exception, new() => Task.FromException(new E());

    public static Task<T> AsyncException<T, E>() where E:Exception, new() => Task.FromException<T>(new E());

    public static Task NotImplementedAsync() => AsyncException<NotImplementedException>();

    public static Task<T> NotImplementedAsync<T>() => AsyncException<T, NotImplementedException>();
}

public struct None
{
    public static readonly None Value = new None(); 
}
