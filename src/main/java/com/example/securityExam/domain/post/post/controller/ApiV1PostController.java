package com.example.securityExam.domain.post.post.controller;

import com.example.securityExam.domain.member.member.entity.Member;
import com.example.securityExam.domain.member.member.service.MemberService;
import com.example.securityExam.domain.post.post.dto.PageDto;
import com.example.securityExam.domain.post.post.dto.PostWithContentDto;
import com.example.securityExam.domain.post.post.entity.Post;
import com.example.securityExam.domain.post.post.service.PostService;
import com.example.securityExam.global.Rq;
import com.example.securityExam.global.dto.RsData;
import com.example.securityExam.global.exception.ServiceException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/posts")
@RequiredArgsConstructor
public class ApiV1PostController {

    private final PostService postService;
    private final Rq rq;
    private final MemberService memberService;

    @GetMapping
    @Transactional(readOnly = true)
    public RsData<PageDto> getItems(@RequestParam(defaultValue = "1") int page,
                                    @RequestParam(defaultValue = "3") int pageSize,
                                    @RequestParam(defaultValue = "title") String keywordType,
                                    @RequestParam(defaultValue = "") String keyword) {
        Page<Post> postPage = postService.getListedItems(page, pageSize, keywordType, keyword);

        return new RsData<>(
                "200-1",
                "글 목록 조회가 완료되었습니다.",
                new PageDto(postPage)
        );

    }

    @GetMapping("/me")
    @Transactional(readOnly = true)
    public RsData<PageDto> getMines(
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "3") int pageSize,
            @RequestParam(defaultValue = "title") String keywordType,
            @RequestParam(defaultValue = "") String keyword) {

        Member actor = rq.getActor();
        Page<Post> pagePost = postService.getMines(actor, page, pageSize, keywordType, keyword);

        return new RsData<>(
                "200-1",
                "내 글 목록 조회가 완료되었습니다.",
                new PageDto(pagePost)
        );
    }

    @GetMapping("/{id}")
    @Transactional(readOnly = true)
    public RsData<PostWithContentDto> getItem(@PathVariable long id) {
        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        // 비공개 글인 경우에만 인증을 하고 읽어본다. 공개글인 경우 로그인 하지 않은 사람도 확인 가능
        if (!post.isPublished()) {
            Member actor = rq.getActor();
            post.canRead(actor);
        }

        return new RsData<>(
                "200-1",
                "%d번 글을 조회하였습니다.".formatted(id),
                new PostWithContentDto(post)
        );
    }

    record WriteReqBody(@NotBlank String title,
                        @NotBlank String content,
                        boolean published,
                        boolean listed) {
    }

    @PostMapping
    @Transactional
    public RsData<PostWithContentDto> write(@Valid @RequestBody WriteReqBody body) {

        Member actor = rq.getActor();
        Post post = postService.write(actor, body.title(), body.content(), body.published(), body.listed());

        return new RsData<>(
                "201-1",
                "%d번 글 작성 완료되었습니다.".formatted(post.getId()),
                new PostWithContentDto(post)
        );
    }

    record ModifyReqBody(@NotBlank String title, @NotBlank String content) {
    }

    @PutMapping("/{id}")
    @Transactional
    public RsData<PostWithContentDto> modify(@Valid @RequestBody ModifyReqBody body,
                                             @PathVariable long id) {
        Member actor = rq.getActor();

        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        if (post.canModify(actor)) {
            postService.modify(post, body.title(), body.content());

        }
        return new RsData<>(
                "200-1",
                "%d번 글 수정이 완료되었습니다.".formatted(post.getId()),
                new PostWithContentDto(post)
        );
    }

    @DeleteMapping("/{id}")
    @Transactional
    public RsData<Void> delete(@PathVariable long id) {
        Member actor = rq.getActor();

        Post post = postService.getItem(id).orElseThrow(
                () -> new ServiceException("404-1", "존재하지 않는 글입니다.")
        );

        if (post.canDelete(actor)) {
            postService.delete(post);
        }

        return new RsData<>(
                "200-1",
                "%d번 글 삭제 완료되었습니다.".formatted(id)
        );
    }


}
