package org.stepup.cinesquareapis.movie.controller;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import org.stepup.cinesquareapis.movie.service.MovieDbLoadingService;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@RequiredArgsConstructor
@Tag(name = "7 DB-loading", description = "DB 적재 관련 API (담당자 외 사용 금지)")
@RequestMapping("db-loading")
@RestController
public class MovieDbLoadingController {

    private final MovieDbLoadingService movieDbLoadingService;

    /**
     * 한국영화진흥원 API 영화 생성 (최초 DB), 100개씩만 호출하기
     *
     * @return
     */
    @Hidden
    @PostMapping("kofics")
    public void createKoficMovies(@RequestParam("current_page") int currentPage, @RequestParam("item_per_page") int itemPerPage
            , @RequestParam("start_production_year") int startProductionYear, @RequestParam("end_production_year") int endProductionYear
            , @RequestParam("open_start_date") int openStartDate) {
        // 영화 기본 정보 저장
        int[] createdMovieIds = movieDbLoadingService.saveKoficMovies(currentPage, itemPerPage, startProductionYear, endProductionYear, openStartDate);

        movieDbLoadingService.crawlMovieSubInfo(createdMovieIds);
    }

    /**
     * 한국영화진흥원 API 영화 생성 (단 건)
     *
     * @return
     */
    @PostMapping("kofic/{kofic_movie_code}")
    public void createKoficMovie(@PathVariable("kofic_movie_code") String koficMovieCode) {
        // 영화 기본 정보 저장
        int createdMovieId = movieDbLoadingService.saveKoficMovie(koficMovieCode);

        if (createdMovieId > 0) {
            int[] createdMovieIds = {createdMovieId};
            movieDbLoadingService.crawlMovieSubInfo(createdMovieIds);
        }
    }

    /**
     * movie_id로 썸네일 다운로드
     *
     * @return
     */
    @PostMapping("cine/{movie_id}/thumbnail")
    public void updateMovieSubInfo(int movieId) {
        int[] arr = {movieId};
        movieDbLoadingService.crawlMovieSubInfo(arr);
    }

    /**
     * 박스오피스 수동 업로드 (업로드 하고자 하는 주의 다음주 월요일 날짜를 yyyyMMdd 형식으로 입력)
     *
     * @return
     */
    @PostMapping("cine/boxoffice")
    public void createBoxofficeManual(@RequestParam("monday_date") String mondaDayte) throws IOException {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        movieDbLoadingService.saveMovieBoxoffice(10, LocalDate.parse(mondaDayte, formatter));
    }

    /**
     * KOFIC 영화 코드로 썸네일 다운로드 (테스트)
     *
     * @return
     */
    public void createMoviePoster(@RequestParam("kofic_movie_code") String koficMovieCode) {
        String[] arr = {koficMovieCode};
        movieDbLoadingService.crawlAndDownloadImages(arr);
    }
}