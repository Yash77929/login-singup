package in.sp.main.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import in.sp.main.entities.User;
import in.sp.main.repositories.UserRepository;

@Service
public class UserServiceImpl implements UserService{
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public boolean registerUser(User user) {
		try {
			userRepository.save(user);
			return true;
		}
		catch(Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public User loginUser(String email, String password) {
		User validUser = userRepository.findByEmail(email);
		if(validUser != null && validUser.getPassword().equals(password)) {
			return validUser;
		}
		return null;
	}
	@Override
	public User findByEmail(String email) {
		return userRepository.findByEmail(email);
	}
}
