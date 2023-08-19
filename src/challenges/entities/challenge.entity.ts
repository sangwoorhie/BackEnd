import {
  Check,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity()
@Check(`"userNumberLimit" >= 2 AND "userNumberLimit" <= 10`)
export class Challenge {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    type: 'varchar',
    nullable: false,
  })
  title: string;

  @Column({
    type: 'varchar',
    nullable: false,
  })
  goal: string;

  @Column({
    type: 'text',
    nullable: false,
  })
  imgUrl: string;

  @Column({
    type: 'date',
    nullable: false,
  })
  startDate: string;

  @Column({
    type: 'int',
    nullable: false,
  })
  challengWeek: number;

  @Column({
    type: 'date',
    nullable: false,
  })
  endDate: string;

  @Column({
    type: 'int',
    nullable: false,
  })
  userNumberLimit: number;

  @Column()
  publicView: boolean;

  @Column({
    type: 'text',
    nullable: false,
  })
  description: string;

  @Column({
    type: 'int',
    nullable: false,
  })
  hostPoint: number;

  @Column({
    type: 'int',
    nullable: false,
  })
  entryPoint: number;

  @CreateDateColumn()
  createdAt: Date;
}
