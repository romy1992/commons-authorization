package com.commons.authorization.resource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(
    origins = {
      "http://localhost:8100",
      "http://localhost:8200",
      "http://localhost:8101",
      "http://localhost:8201",
      "http://localhost"
    })
@RequestMapping("api")
public abstract class FNResourceRoles<M, P, R extends JpaRepository<?, ?>> {

  @Autowired public R repository;

  @PostMapping("save")
  public abstract ResponseEntity<?> insert(@RequestBody M model);

  @GetMapping("getLogin/{email}/{password}")
  public abstract M getLogin(
      @PathVariable("email") String email, @PathVariable("password") String password);

  @GetMapping("getLogin/{email}")
  public abstract M getByEmail(@PathVariable("email") String email);

  @PutMapping("update")
  public abstract M update(@RequestBody M model);

  @DeleteMapping("delete/{primaryKey}")
  public abstract boolean deleteById(@PathVariable("primaryKey") P primaryKey);

  @GetMapping("getAll")
  public abstract List<M> getAll();

  @GetMapping("search")
  public abstract List<M> search(M model);
}
