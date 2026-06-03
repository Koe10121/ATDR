import Vue from "vue";
import Vuex from "vuex";
Vue.use(Vuex);

import DialogMessages from "./modules/Dialog/index";
import Setting from './modules/Setting/index'
import Auth from "./modules/Authen/index";
import Security from "./modules/Security/index";
import Accounts from './modules/Accounts/index'
import Training from './modules/Training/index'


const state = {
  XAccessToken: '',
  sidebarShow: 'responsive',
  sidebarMinimize: false,
  asideShow: false,
  darkMode: false
}

const mutations = {
  toggleSidebarDesktop (state) {
    const sidebarOpened = [true, 'responsive'].includes(state.sidebarShow)
    state.sidebarShow = sidebarOpened ? false : 'responsive'
  },
  toggleSidebarMobile (state) {
    const sidebarClosed = [false, 'responsive'].includes(state.sidebarShow)
    state.sidebarShow = sidebarClosed ? true : 'responsive'
  },
  set (state, [variable, value]) {
    state[variable] = value
  },
  toggle (state, variable) {
    state[variable] = !state[variable]
  }
}


export default new Vuex.Store({
  state,
  mutations,
  modules : {
    dialog: DialogMessages,
    setting : Setting,
    //
    auth : Auth,
    security: Security,
    accounts: Accounts,
    training: Training,
    

  }
});
