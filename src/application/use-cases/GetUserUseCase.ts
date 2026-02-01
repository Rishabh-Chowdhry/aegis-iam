import { User } from "../../domain/entities/User";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";

export interface GetUserRequest {
  userId: string;
  tenantId: string;
}

export interface GetUserResponse {
  user: User;
}

export class GetUserUseCase {
  constructor(private userRepository: IUserRepository) {}

  async execute(request: GetUserRequest): Promise<GetUserResponse> {
    const { userId, tenantId } = request;

    const user = await this.userRepository.findById(userId, tenantId);
    if (!user) {
      throw new Error("User not found");
    }

    return { user };
  }
}
