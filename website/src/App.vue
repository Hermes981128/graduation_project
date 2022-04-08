<template>
  <el-form>
    <el-form-item label="UserName">
      <el-input v-model="UserName"></el-input>
    </el-form-item>
    <el-form-item label="PassWord">
      <el-input v-model="PassWord" ></el-input>
    </el-form-item>
    <el-form-item label="" class="el-form-item__content">
      <el-button type="primary" @click="submit">Submit</el-button>
    </el-form-item>
  </el-form>
</template>

<script>
export default {
  name: 'App',
  components: {}
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
  margin-top: 60px;
}
</style>
