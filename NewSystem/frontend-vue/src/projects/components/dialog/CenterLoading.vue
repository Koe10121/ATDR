<template>
    <div v-show="loadings">
      <div tabindex="-1" role="dialog" class="modal overflow-auto fade show d-block">
        <div role="document" class="modal-dialog modal-dialog-centered w-100">
          <div class="text-center w-100">
            <div role="status" aria-hidden="false" :aria-label="$t('common.loading')" class="spinner-border text-primary" style="width: 4rem; height: 4rem;"></div>
          </div>
        </div>
      </div>
      <div class="modal-backdrop fade show"></div>
    </div>
</template>

<script>

    import {mapGetters} from 'vuex'

    export default {
        name: 'CenterLoading',
        data: function () {
            return {
              // loadings: false
            }
        },
        mounted() {

        },

        created() {
        },

        beforeDestroy() {

        },

        methods: {},

        computed: {
            ...mapGetters({
                loadings: 'dialog/loading'
            })
        },

        watch: {

        }
    }
</script>
