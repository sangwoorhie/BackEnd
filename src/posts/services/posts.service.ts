import { Injectable, NotImplementedException } from '@nestjs/common';
import { CreatePostDto } from '../dto/create-post.dto';
import { UpdatePostDto } from '../dto/update-post.dto';
import { PostsRepository } from '../repositories/posts.repository';

@Injectable()
export class PostsService {
  constructor(private readonly postsRepository: PostsRepository) {}

  // 오운완 인증 게시글 생성
  async createPost(post: CreatePostDto, challengeId: number, userId: number) {
    const { description, imgUrl } = post;

    if (!post.description) {
      throw new NotImplementedException('내용을 모두 입력해주세요.');
    }

    await this.postsRepository.createPost(
      description,
      imgUrl,
      challengeId,
      userId,
    );
  }

  // 오운완 전체 조회
  async getAllPost(challengeId: number) {
    return await this.postsRepository.getAllPost(challengeId);
  }

  // 오운완 상세 조회
  async getOnePost(postId: number) {
    return await this.postsRepository.getOnePost(postId);
  }

  // 오운완 삭제
  async deletePost(postId: number) {
    return await this.postsRepository.deletePost(postId);
  }
}
