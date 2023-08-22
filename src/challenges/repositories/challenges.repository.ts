import { UserRepository } from 'src/users/repositories/users.repository';
import {
  Injectable,
  Logger,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { DataSource, Repository } from 'typeorm';
import { Challenge } from '../entities/challenge.entity';
import { Challenger } from '../entities/challenger.entity';
import { User } from 'src/users/entities/user.entity';
import { CreateChallengeDto } from '../dto/create-challenge.dto';
import { LessThan } from 'typeorm';
import { Position } from '../challengerInfo';

@Injectable()
export class ChallengesRepository extends Repository<Challenge> {
  constructor(
    private readonly dataSource: DataSource,
    private readonly logger: Logger,
    private readonly userRepository: UserRepository,
  ) {
    super(Challenge, dataSource.createEntityManager());
  }

  // 도전 생성 (재용)
  async createChallenge(Challenge: CreateChallengeDto): Promise<Challenge> {
    const newChallenge = await this.create(Challenge);
    return await this.save(newChallenge);
  }

  // 도전 목록조회
  async getChallenges(): Promise<Challenge[]> {
    const challenges = await this.find();
    return challenges;
  }

  // 도전 상세조회
  async getChallenge(challengeId: number): Promise<Challenge> {
    const challenge = await this.findOne({
      where: { id: challengeId },
    });
    return challenge;
  }

  // 도전 삭제 (상우, 재용)
  async deleteChallenge(challengeId): Promise<any> {
    const result = await this.delete(challengeId);
    return result;
  }

  // // 자동삭제 (도전 시작일이 지나고 사용자가 1명(본인)밖에 없을 경우)
  // async automaticDelete(): Promise<void> {
  //   const today = new Date().toISOString();
  //   const challengerCount = await this.getChallengerCount(challengeId);
  //   const challengesToDelete = await this.find({
  //     where: {
  //       startDate: LessThan(today),
  //     },
  //   });

  //   if (challengesToDelete.length > 0 && challengerCount <= 1) {
  //     await this.remove(challengesToDelete);
  //     this.logger.debug(
  //       `도전 시작일이 경과되었으나 도전 참가자가 없어서, 회원님의 ${challengesToDelete} 도전이 삭제되었습니다.`,
  //     );
  //   }
  // }

  // 도전 친구초대
  async inviteChallenge(challengeId: number, invitedUser: User): Promise<void> {
    const challenge = await this.getChallenge(challengeId);
    if (!challenge) {
      throw new NotFoundException('도전 게시글을 찾을 수 없습니다.');
    }

    // 내가 팔로우하는 유저목록
    const followedUsers = await this.getCurrentUserById(invitedUser.id);
    // 초대된 사용자가 내 친구인지 확인
    const isFollowing = followedUsers.some(
      (user: { id: number }) => user.id === invitedUser.id,
    );
    if (!isFollowing || isFollowing == undefined) {
      throw new UnauthorizedException(
        '해당 회원과 친구가 아니므로 초대할 수 없습니다.',
      );
    }
    // 초대된 참가자가 이미 참가한 도전자인지 확인
    const existingChallenger = await this.createQueryBuilder('challenger')
      .where('challenger.challengeId = :challengeId', { challengeId })
      .andWhere('challenger.userId = :userId', { userId: invitedUser.id })
      .getOne();
    if (existingChallenger) {
      throw new BadRequestException('이미 도전에 참가한 회원입니다.');
    }

    const newChallenger: Partial<Challenger> = {
      challengeId,
      userId: invitedUser.id,
      type: Position.GUEST,
      done: false,
    };

    await this.createQueryBuilder('challenger')
      .insert()
      .values(newChallenger)
      .execute();
  }

  // 회원 정보조회 // CurrentUser
  async getCurrentUserById(userId: number): Promise<any> {
    const queryBuilder = await this.userRepository
      .createQueryBuilder('user')
      .select([
        'user.id',
        'user.name',
        'user.email',
        'user.gender',
        'user.age',
        'user.height',
        'user.comment',
        'user.point',
      ])
      .where('user.id = :userId', { userId })
      .leftJoinAndSelect('user.followers', 'follower')
      .leftJoinAndSelect('follower.followed', 'followed')
      .addSelect(['followed.id', 'followed.name', 'followed.imgUrl']);

    const users = await queryBuilder.getMany();

    const transformedUsers = users.map((user) => {
      const transformedFollowers = user.followers.map((follower) => {
        return {
          id: follower.followed.id,
          name: follower.followed.name,
          imgUrl: follower.followed.imgUrl,
        };
      });

      return {
        id: user.id,
        name: user.name,
        age: user.age,
        height: user.height,
        email: user.email,
        gender: user.gender,
        comment: user.comment,
        point: user.point,
        followers: transformedFollowers,
      };
    });
    return transformedUsers;
  }

  // 도전자 수 조회 (상우, 재용)
  async getChallengerCount(challengeId: number): Promise<number> {
    const challengersCount = await this.count({
      where: {
        id: challengeId,
      },
    });
    return challengersCount;
  }
}
