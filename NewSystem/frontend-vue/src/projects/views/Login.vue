<template>
  <div class="c-app flex-row align-items-center">
    <CContainer>
      <CRow class="justify-content-center">
        <CCol md="8">
          <CCardGroup>
            <CCard class="p-4">
              <CCardBody>
                <CForm>
                  <div class="text-center mb-3">
                    <img src="@/assets/logo.svg" height="150px"/>
                  </div>
<!--                  <h1>Login</h1>-->
                  <p class="text-muted text-center">{{ $t('auth.loginPage.subtitle') }}</p>
                  <CInput
                    v-model="username"
                    :placeholder="$t('auth.loginPage.username')"
                    autocomplete="username email"
                  >
                    <template #prepend-content><CIcon name="cil-user"/></template>
                  </CInput>
                  <CInput
                    v-model="password"
                    :placeholder="$t('auth.loginPage.password')"
                    type="password"
                    autocomplete="curent-password"
                  >
                    <template #prepend-content><CIcon name="cil-lock-locked"/></template>
                  </CInput>
                  <CRow>
                    <CCol  class="text-right">
                      <CButton color="danger" class="px-4 w-50" @click="onAuthen">{{ $t('auth.loginPage.login') }}</CButton>
                    </CCol>
                  </CRow>
                </CForm>
              </CCardBody>
            </CCard>
            <CCard
              color="danger"
              text-color="white"
              class="text-center py-5 d-md-down-none"
              body-wrapper
            >
              <CCardBody>
                <h2>{{ $t('auth.loginPage.signUp') }}</h2>
                <p>{{ $t('auth.loginPage.signUpText') }}</p>
                <CButton
                  color="light"
                  variant="outline"
                  size="lg"
                >
                  {{ $t('auth.loginPage.registerNow') }}
                </CButton>
              </CCardBody>
            </CCard>
          </CCardGroup>
        </CCol>
      </CRow>
    </CContainer>

    <CenterLoading/>
  </div>

</template>
<script>
  import {mapGetters} from 'vuex'
  import CenterLoading from "@/projects/components/Dialog/CenterLoading";
  export default {
    name: 'Login',
    components: {CenterLoading},
    data () {
      return {
        username:'',
        password:'',
        dialog : {
          statue:false,
          title:"",
          message:""
        }

      }
    },

    mounted() {
      // localStorage.setItem('test','123444')
    },

    created() {
      // var storageHost = createHost([
      //   {
      //     origin: 'http://localhost:8080',
      //     allowedMethods: ['get', 'set', 'remove'],
      //   },
      //   {
      //     origin: 'http://localhost:8081',
      //     allowedMethods: ['get', 'set', 'remove'],
      //   },
      // ]);
      // var bazStorage = createGuest('http://localhost:8080/#/pages/login');
      //
      // // var bazStorage = createGuest(window.location.href === 'http://localhost:8080/#/pages/login'?'http://localhost:8081/#/pages/login':'http://localhost:8080/#/pages/login' );
      // bazStorage.get('tests', function(error, value) {
      //   // value for the key of 'fizz' will be retrieved from localStorage on www.baz.com
      //   console.log("practice",error,value)
      // });
    },

    beforeDestroy() {

    },

    methods: {
      onAuthen() {
        console.log(12)
        // const authCode = await this.$gAuth.getAuthCode()
        // console.log('authCode', authCode)

        // const googleUser = await this.$gAuth.signIn();
        // console.log('googleUser', googleUser)


        // this.login();
        var body = {};
        body.username = btoa(this.username);
        body.password = btoa(this.password);
        this.$store.dispatch("auth/signIn", body)

      },

      async handleClickSignIn(){
        try {
          const googleUser = await this.$gAuth.signIn();
          console.log('user', googleUser)
          this.isSignIn = this.$gAuth.isAuthorized
        } catch (error) {
          // On fail do something
          console.log(error);
          return null;
        }
      },
      login() {
        // googleSdkLoaded(google => {
        //   google.accounts.oauth2
        //       .initCodeClient({
        //         client_id: "225788483142-8pkg8on8nh60ao83ve33ff3lflv2ccvo.apps.googleusercontent.com",
        //         scope: "email profile openid",
        //         redirect_uri: "http://localhost:4000/auth/callback",
        //         callback: response => {
        //           console.log(response)
        //           // if (response.code) {
        //           //   this.sendCodeToBackend(response.code);
        //           // }
        //         }
        //       })
        //       .requestCode();
        // });
      },
    },

    computed:{
      ...mapGetters({
        objJwt:'auth/objJwt',
        dialogError:"auth/dialogError"
      })
    },

    watch: {
      objJwt:function (data) {
        console.log(data)

      },
      dialogError:function (data) {
        this.dialog = data
        console.log(data)
      }
    }
  }

</script>
