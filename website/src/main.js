import {createApp} from 'vue'
import ElementPlus from 'element-plus'
import App from './App.vue'
import 'element-plus/es/components/message/style/css'
import 'element-plus/es/components/message-box/style/css'


const app = createApp(App)
app.use(ElementPlus, {size: 'small', zIndex: 3000})
app.mount('#app')