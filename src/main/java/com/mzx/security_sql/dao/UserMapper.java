package com.mzx.security_sql.dao;


import com.mzx.security_sql.pojo.Role;
import com.mzx.security_sql.pojo.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    User loadUserByUsername(String name);
    List<Role> getUserRolesByUid(Integer id);
}
