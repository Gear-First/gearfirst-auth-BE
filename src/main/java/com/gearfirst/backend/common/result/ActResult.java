package com.gearfirst.backend.common.result;

import com.gearfirst.backend.common.exception.BaseException;
import com.gearfirst.backend.common.response.ErrorResponse;

import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * 추상클래스 - 자식클래스들이 반드시 구현해야하는 공통 틀
 * ActResult자체는 결과의 추상 개념일 뿐 성공/실패/알수없음의 구체적인 상태를 가지지 않음
 */

public abstract class ActResult<A> {
    public enum ResultType { SUCCESS, FAILURE, UNKNOWN  }

    public abstract ResultType getResultType();

    public static final class Success<A> extends ActResult<A>{
        private final A data;
        public Success(A data) { this.data = data; }
        public A getData() { return data; }
        @Override public ResultType getResultType() { return ResultType.SUCCESS; }
    }

    public static final class Failure<A> extends ActResult<A>{
        private final ErrorResponse errorResponse;
        public Failure(ErrorResponse errorResponse) { this.errorResponse = errorResponse; }
        public ErrorResponse getErrorResponse() { return errorResponse; }
        @Override public ResultType getResultType() { return ResultType.FAILURE; }
    }

    public static final class Unknown<A> extends ActResult<A>{
        private final  ErrorResponse errorResponse;
        public Unknown(ErrorResponse errorResponse) { this.errorResponse = errorResponse; }
        public ErrorResponse getErrorResponse() { return errorResponse; }
        @Override public ResultType getResultType() { return ResultType.UNKNOWN; }
    }

    /** method **/
    // success(): 성공 결과를 나타내는 ActResult 객체 생성
    public static <A> ActResult<A> success(A data) {
        return new Success<>(data);
    }
    // failure(): 실패 결과를 나타내는 ActResult 객체 생성
    public static <A> ActResult<A> failure(ErrorResponse errorResponse) {
        return new Failure<>(errorResponse);
    }
    // unknown(): 알 수 없는 결과를 나타내는 ActResult 객체 생성
    public static <A> ActResult<A> unknown(ErrorResponse errorResponse) {
        return new Unknown<>(errorResponse);
    }

    /** Exception-safe context */
    public static <A> ActResult<A> of (Supplier<A> func){
        try{
            return new Success<>(func.get());
        } catch (BaseException e){
            return new Failure<>(new ErrorResponse(e));
        } catch (Exception e){
            return new Unknown<>(new ErrorResponse(e));
        }
    }

    /** functional style **/
    //성공시 데이터 변환
    public <C> ActResult<C> map(Function<A,C> mapper){
        if (this instanceof Success<A> success){
            return new Success<>(mapper.apply(success.getData()));
        }
        if (this instanceof Failure<A> failure){
            return new Failure<>(failure.getErrorResponse());
        }
        return new Unknown<>( ((Unknown<A>) this).getErrorResponse() );
    }

    //성공 시 결과를 또 다른 ActResult로 변환
    public <C> ActResult<C> flatMap(Function<A, ActResult<C>> mapper) {
        if (this instanceof Success<A> s)
            return mapper.apply(s.getData());
        if (this instanceof Failure<A> f)
            return new Failure<>(f.getErrorResponse());
        return new Unknown<>( ((Unknown<A>) this).getErrorResponse() );
    }
    /** UNKNOWN인 경우 재시도 */
    public ActResult<A> recoverUnknown(Supplier<ActResult<A>> retryFunc) {
        if (this instanceof Unknown<A>)
            return retryFunc.get();
        return this;
    }

    /** SUCCESS 시 콜백 실행 */
    public ActResult<A> onSuccess(Consumer<A> func) {
        if (this instanceof Success<A> s) {
            func.accept(s.getData());
        }
        return this;
    }

    /** FAILURE 시 콜백 실행 */
    public ActResult<A> onFailure(Consumer<ErrorResponse> func) {
        if (this instanceof Failure<A> f) {
            func.accept(f.getErrorResponse());
        }
        return this;
    }

    /** UNKNOWN 시 콜백 실행 */
    public ActResult<A> onUnknown(Consumer<ErrorResponse> func) {
        if (this instanceof Unknown<A> u) {
            func.accept(u.getErrorResponse());
        }
        return this;
    }



}

