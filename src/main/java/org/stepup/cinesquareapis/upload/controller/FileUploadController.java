package org.stepup.cinesquareapis.upload.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.stepup.cinesquareapis.upload.service.FileUploadService;

@RestController
@RequiredArgsConstructor
@Tag(name = "6 upload", description = "파일 업로드 API")
@RequestMapping("api/upload")
public class FileUploadController {

    private final FileUploadService fileUploadService;

//    /**
//     * 사용자 프로필 업로드
//     */
//    @PostMapping("users/{user_id}")
//    public ResponseEntity<ResultResponse<Boolean>> profileUpload(
//            @RequestPart(value = "file") MultipartFile multipartFile, @PathVariable("user_id") Integer userId) {
//
//        Boolean data = fileUploadService.userProfileUpload("UA", multipartFile, userId);
//        ResultResponse<Boolean> response = new ResultResponse<>();
//        response.setResult(data);
//
//        return new ResponseEntity<>(response, HttpStatus.OK);
//    }

//    /**
//     * 영화 포스터 업로드
//     */
//    @Operation(summary = "영화 포스터 업로드(다중)",
//            description = "UP : User Profile, MO : 영화 포스터, MA : Movie Actor 등 축약어로 구분하고있음"
//    )
//    @PostMapping("movies/{movie_id}")
//    public ResponseEntity<ResultResponse<Boolean>> moviePosterUpload(
//            @RequestPart(value = "file") MultipartFile[] multipartFile, @PathVariable("movie_id") Integer movieId) throws JsonProcessingException {
//
//        Boolean data = fileUploadService.moviePosterUpload("MO", multipartFile, movieId);
//        ResultResponse<Boolean> response = new ResultResponse<>();
//        response.setResult(data);
//
//        return new ResponseEntity<>(response, HttpStatus.OK);
//    }
}
