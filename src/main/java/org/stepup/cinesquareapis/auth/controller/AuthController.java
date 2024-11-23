package org.stepup.cinesquareapis.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.stepup.cinesquareapis.auth.dto.SignInRequest;
import org.stepup.cinesquareapis.auth.dto.SignInResponse;
import org.stepup.cinesquareapis.auth.dto.SignUpRequest;
import org.stepup.cinesquareapis.auth.dto.SignUpResponse;
import org.stepup.cinesquareapis.auth.service.AuthService;
import org.stepup.cinesquareapis.common.dto.DataResponse;
import org.stepup.cinesquareapis.common.dto.ResultResponse;

@RequiredArgsConstructor
@Tag(name = "1 auth", description = "Auth API")
@RequestMapping("api/auth")
@RestController
public class AuthController {
    private final AuthService authService;

    /**
     * 계정 존재 여부 확인
     */
    @Operation(
            summary = "계정 존재 여부 확인",
            description = "존재하는 계정이면 true, 존재하지 않는 계정이면 false 반환"
    )
    @GetMapping("check-account/{account}")
    public ResponseEntity<ResultResponse<Boolean>> checkAccount(@PathVariable("account") String account) {
        boolean result = authService.checkAccount(account);

        return ResponseEntity.ok(new ResultResponse(result));
    }

    /**
     * 회원가입
     */
    @Operation(summary = "회원가입")
    @ApiResponses({
            @ApiResponse(responseCode = "200", useReturnTypeSchema = true),
            @ApiResponse(responseCode = "20102", description = "이미 존재하는 account를 사용한 경우의 에러코드", content = @Content())
    })
    @PostMapping("sign-up")
    public ResponseEntity<DataResponse<SignUpResponse>> signUp(@RequestBody SignUpRequest request) {
        SignUpResponse response = authService.signUp(request);

        return ResponseEntity.ok(new DataResponse(response));
    }

    /**
     * 로그인 (AccessToken, RefreshToken 발급)
     */
    @Operation(summary = "로그인 (AccessToken, RefreshToken 발급)")
    @ApiResponses({
            @ApiResponse(responseCode = "200", useReturnTypeSchema = true),
            @ApiResponse(responseCode = "20100", description = "account로 조회한 user가 존재하지 않는 경우의 에러코드", content = @Content()),
            @ApiResponse(responseCode = "20101", description = "잘못된 비밀번호로 요청하는 경우의 에러코드", content = @Content())
    })
    @PostMapping("sign-in")
    public ResponseEntity<DataResponse<SignInResponse>> signIn(@RequestBody SignInRequest request) {
        SignInResponse response = authService.signIn(request);

        return ResponseEntity.ok(new DataResponse(response));
    }
}