<template>
  <q-card style="min-width: 400px">
    <q-card-section class="row items-center">
      <div v-if="mode === 'add'" class="text-h6">Add Disk Space Check</div>
      <div v-else-if="mode === 'edit'" class="text-h6">Edit Disk Space Check</div>
      <q-space />
      <q-btn icon="close" flat round dense v-close-popup />
    </q-card-section>

    <q-form @submit.prevent="mode === 'add' ? addCheck() : editCheck()">
      <q-card-section>
        <q-select
          :disable="this.mode === 'edit'"
          outlined
          v-model="diskcheck.disk"
          :options="diskOptions"
          label="Disk"
        />
      </q-card-section>
      <q-card-section>
        <q-input
          outlined
          v-model.number="diskcheck.threshold"
          label="Threshold (%)"
          :rules="[
            val => !!val || '*Required',
            val => val >= 1 || 'Minimum threshold is 1',
            val => val < 100 || 'Maximum threshold is 99',
          ]"
        />
      </q-card-section>
      <q-card-section>
        <q-select
          outlined
          dense
          options-dense
          v-model="diskcheck.fails_b4_alert"
          :options="failOptions"
          label="Number of consecutive failures before alert"
        />
      </q-card-section>
      <q-card-actions align="right">
        <q-btn v-if="mode === 'add'" label="Add" color="primary" type="submit" />
        <q-btn v-else-if="mode === 'edit'" label="Edit" color="primary" type="submit" />
        <q-btn label="Cancel" v-close-popup />
      </q-card-actions>
    </q-form>
  </q-card>
</template>

<script>
import axios from "axios";
import { mapState, mapGetters } from "vuex";
import mixins from "@/mixins/mixins";
export default {
  name: "DiskSpaceCheck",
  props: {
    agentpk: Number,
    policypk: Number,
    mode: String,
    checkpk: Number,
  },
  mixins: [mixins],
  data() {
    return {
      diskcheck: {
        disk: null,
        check_type: "diskspace",
        threshold: 25,
        fails_b4_alert: 1,
      },
      diskOptions: [],
      failOptions: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    };
  },
  methods: {
    setDiskOptions() {
      if (this.policypk) {
        axios.get("/checks/getalldisks/").then(r => {
          this.diskOptions = r.data;
          this.diskcheck.disk = "C:";
        });
      } else {
        this.diskOptions = this.agentDisks.map(i => i.device);
        this.diskcheck.disk = this.diskOptions[0];
      }
    },
    getCheck() {
      axios.get(`/checks/${this.checkpk}/check/`).then(r => (this.diskcheck = r.data));
    },
    addCheck() {
      const pk = this.policypk ? { policy: this.policypk } : { pk: this.agentpk };
      const data = {
        ...pk,
        check: this.diskcheck,
      };
      axios
        .post("/checks/checks/", data)
        .then(r => {
          this.$emit("close");
          this.reloadChecks();
          this.notifySuccess(r.data);
        })
        .catch(e => this.notifyError(e.response.data.non_field_errors));
    },
    editCheck() {
      axios
        .patch(`/checks/${this.checkpk}/check/`, this.diskcheck)
        .then(r => {
          this.$emit("close");
          this.reloadChecks();
          this.notifySuccess(r.data);
        })
        .catch(e => this.notifyError(e.response.data.non_field_errors));
    },
    reloadChecks() {
      if (this.policypk) {
        this.$store.dispatch("automation/loadPolicyChecks", this.policypk);
      } else {
        this.$store.dispatch("loadChecks", this.agentpk);
      }
    },
  },
  computed: {
    ...mapGetters(["agentDisks"]),
  },
  created() {
    if (this.mode === "add") {
      this.setDiskOptions();
    } else if (this.mode === "edit") {
      this.getCheck();
    }
  },
};
</script>