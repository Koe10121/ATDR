<template>
    <div>

      <CToaster :autohide="4000">

        <CToast
            v-for="(toast, index) in toasts"
            :key="index"
            :color="toast.color || 'success'"
            :show="true"
            @update:show="() => onDone(index)"
        >
          {{ toast.message || toast }}
        </CToast>
      </CToaster>

    </div>
</template>

<script>

    import {mapGetters} from 'vuex'

    export default {
        name: 'CenterToaster',
        data: function () {
            return {

            }
        },
        mounted() {

        },

        created() {
        },

        beforeDestroy() {

        },

        methods: {
          onDone(index){
            // Remove specific toast from array
            const updatedToasts = [...this.toasts]
            updatedToasts.splice(index, 1)
            this.$store.commit("dialog/toasts", updatedToasts)
          }
        },

        computed: {
            ...mapGetters({
              toasts: 'dialog/toasts'
            })
        },

        watch: {
          toasts: function (value) {
            console.log('Toasts changed:', value)
          }

        }
    }
</script>
